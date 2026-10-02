# Nobleson

JWT for Java, without the ceremony.

Working with JSON Web Tokens in Java usually means gluing together Base64URL encoding, a JSON library, the `javax.crypto` and `java.security` signing APIs, and a pile of manual checks for expiry, issuer, and audience. Python has `PyJWT`, JavaScript has `jsonwebtoken`, and in both of them you get the job done in a line or two. Nobleson brings that same feeling to Java. You build a token, sign it, and verify it in a single fluent chain, and the sensible security defaults are already switched on.

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

That is a complete, signed, expiring JWT.

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
- [Security notes](#security-notes)
- [Using Nobleson in Spring Boot](#using-nobleson-in-spring-boot)
- [Logout and revoking tokens](#logout-and-revoking-tokens)
- [Performance and scaling](#performance-and-scaling)
- [Requirements](#requirements)
- [Roadmap](#roadmap)
- [License](#license)

## Why Nobleson

**One chain to a token.** There are no helper classes to wire up and no builders nested inside builders. You set your claims, say how to sign, and call `.generate()`.

**Safe by default.** The parser rejects algorithm confusion attacks, checks `exp` and `nbf` for you, and compares HMAC signatures in constant time. There is no `none` algorithm, and that is deliberate.

**Every common algorithm.** HMAC, RSA, and ECDSA, each in the 256, 384, and 512 variants.

**Small surface.** It is a handful of classes you can learn in one sitting. The only runtime dependency is Jackson for JSON.

## Installation

Nobleson is a standard Maven artifact. Add it to your `pom.xml`:

```xml
<dependency>
    <groupId>io.github.eselase-noble</groupId>
    <artifactId>nobleson-jwt</artifactId>
    <version>0.1.0</version>
</dependency>
```

Using Gradle:

```groovy
implementation 'io.github.eselase-noble:nobleson-jwt:0.1.0'
```

### From JitPack

If you want it straight from the source tag without waiting for a Central release, JitPack builds it on demand. Add the repository and depend on the tag:

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<dependency>
    <groupId>com.github.Eselase-Noble</groupId>
    <artifactId>jwt</artifactId>
    <version>v0.1.0</version>
</dependency>
```

Maintainers publishing a new release should follow [PUBLISHING.md](PUBLISHING.md).

## Quick start

```java
import io.nobleson.jwt.Nobleson;
import io.nobleson.jwt.Jwt;
import io.nobleson.jwt.Keys;
import io.nobleson.jwt.algorithm.Algorithms;

import javax.crypto.SecretKey;
import java.time.Duration;

// A signing key. In production, load a stable secret from config. If you
// generate a fresh one on every start, yesterday's tokens stop verifying.
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

Start from `Nobleson.builder()`. Registered claims have their own methods, and anything else goes through `claim(name, value)`.

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

A few things worth knowing:

- `issuedNow()` sets `iat` to the current instant.
- `expiresIn(Duration)` sets `exp` relative to now, while `expiration(Instant)` sets it to an absolute time.
- `claim(name, null)` removes a claim.
- `signWith(...)` is required. Calling `generate()` without it throws.

## Verifying tokens

Start from `Nobleson.parser()`. The verifying algorithm is required, and everything else is optional.

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

1. The token has three Base64URL parts that decode to JSON, otherwise `MalformedJwtException`.
2. The header `alg` equals the verifier's algorithm, otherwise `SignatureException`.
3. The signature matches, otherwise `SignatureException`.
4. `exp` is not in the past and `nbf` is not in the future, within `clockSkew`, otherwise `ExpiredJwtException` or `PrematureJwtException`.
5. Every `require(...)` expectation holds, otherwise `InvalidClaimException`.

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

Date claims (`exp`, `nbf`, `iat`) are stored as seconds since the epoch, as the spec requires, and handed back to you as an `Instant`.

## Algorithms

Pick an algorithm from `Algorithms`. The same factory serves signing and verifying. Pass a secret or private key to sign, and a public key to verify.

| Family | Methods                       | Key type            |
|--------|-------------------------------|---------------------|
| HMAC   | `hs256` `hs384` `hs512`       | shared secret (`byte[]` or `String`) |
| RSA    | `rs256` `rs384` `rs512`       | `KeyPair`, `PrivateKey`, or `PublicKey` |
| ECDSA  | `es256` `es384` `es512`       | `KeyPair`, `PrivateKey`, or `PublicKey` |

```java
// HMAC: one shared secret signs and verifies.
Algorithm hmac = Algorithms.hs256("a-long-shared-secret");

// RSA and EC: sign with the private key, verify with the public key.
KeyPair pair = Keys.rsaKeyPair();
String token = Nobleson.builder().subject("u").signWith(Algorithms.rs256(pair.getPrivate())).generate();
Jwt jwt      = Nobleson.parser().verifyWith(Algorithms.rs256(pair.getPublic())).parse(token);
```

For ECDSA, Nobleson quietly converts between the JDK's DER signature encoding and the `R || S` form the JWT spec requires (RFC 7518 section 3.4), so your ES256, ES384, and ES512 tokens interoperate with other compliant libraries.

## Generating keys

Need a key and don't have one yet? `Keys` makes strong ones in a single call.

```java
SecretKey secret = Keys.hmacSecret();          // 256-bit, for HS256
SecretKey big    = Keys.hmacSecret(512);        // for HS512

KeyPair rsa      = Keys.rsaKeyPair();           // 2048-bit, for RS*
KeyPair ec256    = Keys.ecKeyPair();            // P-256, for ES256
KeyPair ec512    = Keys.ecKeyPair("secp521r1"); // P-521, for ES512
```

Generate your keys once and store them. A key minted at startup only verifies tokens from that same run.

## Error handling

Every failure is an unchecked exception under `io.nobleson.jwt.exception`. Catch the base type for a blanket "invalid token", or catch a specific type when you want to react differently.

```java
import io.nobleson.jwt.exception.*;

try {
    Jwt jwt = Nobleson.parser().verifyWith(alg).parse(token);
    // ... trusted ...
} catch (ExpiredJwtException e) {
    // prompt a refresh
} catch (JwtException e) {
    // malformed, bad signature, or wrong claim, so reject it
}
```

| Exception                | Meaning                                            |
|--------------------------|----------------------------------------------------|
| `MalformedJwtException`  | Not three parts, bad Base64URL, or bad JSON        |
| `SignatureException`     | Signature mismatch, or `alg` does not match verifier |
| `ExpiredJwtException`    | `exp` is in the past                               |
| `PrematureJwtException`  | `nbf` is in the future                             |
| `InvalidClaimException`  | A `require(...)` expectation failed                |
| `JwtException`           | Base type of all of the above                      |

## Security notes

**No `none` algorithm.** Unsigned tokens are a classic footgun, so Nobleson simply does not offer them.

**Algorithm confusion is blocked.** The parser insists that the token's `alg` header matches the algorithm you chose to verify with, so an attacker cannot hand you an HMAC token signed with your public RSA key as the secret.

**Constant-time HMAC comparison** through `MessageDigest.isEqual`, so signature checks do not leak timing information.

**Pick keys that match the algorithm.** Use a secret at least as long as the hash for HMAC (256 bits or more for HS256), 2048-bit RSA or larger, and the matching curve for EC.

**Always set `exp`.** Short-lived tokens limit the damage if one leaks.

## Using Nobleson in Spring Boot

Nobleson ships a ready-made `JwtService` that speaks Spring Security's `UserDetails`, so you do not hand-roll the token util at all. You call `generateToken(userDetails)`, `extractUsername(token)`, and `isTokenValid(token, userDetails)`. It drops into any Spring or Spring Boot project without conflicts, and the same artifact works on Spring Boot 2 (`javax.servlet`) and Spring Boot 3 (`jakarta.servlet`); you just match the filter imports to your version. Here is the whole JWT setup for a stateless REST API.

First, expose the algorithm and the service as beans, with the secret coming from `application.yml`:

```java
@Configuration
public class JwtConfig {

    @Bean
    public Algorithm jwtAlgorithm(@Value("${app.jwt.secret}") String secret) {
        return Algorithms.hs256(secret);   // swap for rs256(...) to use RSA keys
    }

    @Bean
    public JwtService jwtService(Algorithm algorithm) {
        return new JwtService(algorithm, Duration.ofHours(1));   // token lifetime
    }
}
```

```yaml
# application.yml
app:
  jwt:
    secret: ${JWT_SECRET:change-me-to-a-long-random-value}
```

You do not write `JwtService` yourself. Nobleson provides it at `io.nobleson.jwt.spring.JwtService`, and it gives you the methods a Spring JWT util normally hand-rolls:

```java
// Issue
String  token  = jwtService.generateToken(userDetails);                       // sign for a user
String  token2 = jwtService.generateToken(Map.of("tenant", "acme"), userDetails); // with extra claims
String  fresh  = jwtService.refreshToken(token);                              // re-issue with a new expiry

// Validate
boolean ok      = jwtService.validateToken(token);                            // verify and check expiry
boolean okForMe = jwtService.isTokenValid(token, userDetails);                // ... and that it is this user's
boolean dead    = jwtService.isTokenExpired(token);                           // past its expiry?
Duration left   = jwtService.getRemainingValidity(token);                     // time until it expires

// Read
String username = jwtService.extractUsername(token);                          // the subject
List<String> roles = jwtService.extractRoles(token);                          // the roles claim
var authorities = jwtService.extractAuthorities(token);                       // roles as GrantedAuthority
Instant exp     = jwtService.extractExpiration(token);
String  email   = jwtService.extractClaim(token, c -> c.get("email", String.class));
Map<String, Object> all = jwtService.extractAllClaims(token);

// Authenticate (ready to drop into the SecurityContext)
Authentication auth = jwtService.getAuthentication(token);
```

Next comes the filter that authenticates the request. This is the part that usually sprawls, and with the built-in service it is only a few lines. `resolveToken` reads the token from wherever you configured (Bearer header by default), and `getAuthentication` turns a valid token into a Spring `Authentication` (Spring Boot 3 and `jakarta` imports shown):

```java
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    public JwtAuthFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String token = jwtService.resolveToken(
                request.getHeader(HttpHeaders.AUTHORIZATION),
                request.getHeader(HttpHeaders.COOKIE));

        if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                // One verification per request: getAuthentication verifies the token
                // (signature, expiry, revocation) and builds the Authentication from it.
                SecurityContextHolder.getContext().setAuthentication(jwtService.getAuthentication(token));
            } catch (JwtException e) {
                // Invalid, expired, or revoked: stay unauthenticated and let the chain return 401 or 403.
            }
        }
        chain.doFilter(request, response);
    }
}
```

If you prefer to look the user up fresh on every request (for example to pick up a role change immediately), use the `UserDetails` flow instead: `jwtService.extractUsername(token)`, then `userDetailsService.loadUserByUsername(username)`, then `jwtService.isTokenValid(token, user)`.

Finally, wire the filter into the security chain:

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

That is the entire integration. Your login endpoint calls `jwtService.generateToken(userDetails)`, every other endpoint is protected automatically, and `@PreAuthorize("hasRole('ADMIN')")` works off the authorities Nobleson stored in the token.

If you are on Spring Boot 2, use the same code with `javax.servlet.*` imports in place of `jakarta.servlet.*`. The Nobleson side is identical.

### Bearer header or cookie

By default the token is read from the `Authorization: Bearer` header, which is what most APIs and mobile clients use. Browser apps often prefer an `HttpOnly` cookie so the token is never exposed to JavaScript. You choose per service, and the filter above does not change either way because `resolveToken` handles both:

```java
@Bean
public JwtService jwtService(Algorithm algorithm) {
    return new JwtService(algorithm, Duration.ofHours(1))
            .tokenSource(TokenSource.COOKIE)   // default is TokenSource.BEARER
            .cookieName("accessToken");        // default cookie name
}
```

When you use cookies, set the token on the login response and clear it on logout with the hardened helpers (they add `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and a `Max-Age` matching the token lifetime):

```java
// login
response.addHeader(HttpHeaders.SET_COOKIE, jwtService.buildCookie(token));

// logout
response.addHeader(HttpHeaders.SET_COOKIE, jwtService.buildClearCookie());
```

Both `extractBearerToken(headerValue)` and `extractCookieToken(cookieHeader, name)` are also available as static methods if you want to resolve the token yourself.

## Logout and revoking tokens

A signed JWT is valid until it expires, and the server keeps no copy of it, so there is nothing to delete when a user logs out. Real "log out now" therefore needs a small amount of server-side state: a denylist of token ids that should no longer be accepted. Nobleson gives every token a unique `jti` when `JwtService` issues it, and it will consult a `TokenDenylist` on every verification once you attach one.

Attach a denylist and the `revoke` and `logout` methods start working:

```java
@Bean
public JwtService jwtService(Algorithm algorithm) {
    return new JwtService(algorithm, Duration.ofHours(1))
            .denylist(new InMemoryTokenDenylist());   // or your own Redis/DB implementation
}
```

```java
// logout endpoint
jwtService.logout(token);          // same as revoke(token)

// from then on
jwtService.validateToken(token);   // false
jwtService.verify(token);          // throws RevokedJwtException
```

`InMemoryTokenDenylist` fits a single instance and forgets each entry once the token would have expired anyway, so it stays small. For several instances behind a load balancer, implement `TokenDenylist` over a shared store such as Redis so a logout on one node is seen by all of them:

```java
public class RedisTokenDenylist implements TokenDenylist {

    private final StringRedisTemplate redis;

    public RedisTokenDenylist(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public void revoke(String tokenId, Instant expiry) {
        long ttl = Duration.between(Instant.now(), expiry).getSeconds();
        if (ttl > 0) {
            redis.opsForValue().set("revoked:" + tokenId, "1", Duration.ofSeconds(ttl));
        }
    }

    @Override
    public boolean isRevoked(String tokenId) {
        return redis.hasKey("revoked:" + tokenId);
    }
}
```

If you are not using Spring, the same idea works through the core parser's `check` hook:

```java
Jwt jwt = Nobleson.parser()
        .verifyWith(algorithm)
        .check(t -> !denylist.isRevoked(t.claims().id()))
        .parse(token);
```

For longer sessions, pair short-lived access tokens with `refreshToken(...)` so a stolen token is only useful briefly, and reserve the denylist for immediate logout.

## Performance and scaling

Nobleson is built to sit on a hot request path. A few notes so you get the most from it.

- **Reuse one instance.** `JwtService` and the `Algorithm` objects hold only immutable configuration and keys, so a single instance is safe to share across all threads. As a Spring bean it is a singleton already. Internally there is one shared Jackson `ObjectMapper`, which is the expensive object to create.
- **Verify once per request.** Each `extractUsername`, `extractRoles`, `isTokenValid`, and so on verifies the token again. On a hot path, call `verify(token)` (or `getAuthentication(token)`) one time and read what you need from the returned `Jwt`, rather than chaining several `extract...` calls on the same token.
- **Prefer HMAC unless you need asymmetric keys.** HS256 is markedly faster than RS256 or ES256 because it is symmetric. Reach for RSA or EC only when the verifier must not be able to mint tokens.
- **Revocation checks are O(1).** `InMemoryTokenDenylist` looks up a single id per request and sweeps expired entries only on `revoke`. For several instances, back `TokenDenylist` with Redis so the lookup stays fast and shared.
- **Scale out freely.** Verification is purely local and needs no shared state, so you add instances to add throughput. The only shared state is the denylist, which is why it is an interface you can point at Redis or a database.
- **Keep tokens small.** Fewer and smaller claims mean less to sign, encode, and parse. Put large or rarely needed data behind an id rather than in the token.

### Benchmarks

A JMH harness lives in `src/test/java/io/nobleson/jwt/benchmark`. Run it with:

```bash
mvn -q test-compile exec:exec \
  -Dexec.executable=java -Dexec.classpathScope=test \
  -Dexec.args="-cp %classpath org.openjdk.jmh.Main"
```

It measures sign and verify throughput for HS256, RS256, and ES256 so you can see the numbers on your own hardware. Append a name to run one, for example `...org.openjdk.jmh.Main verifyHs256`.

## Requirements

- Java 17 or newer.
- Jackson (`jackson-databind`), pulled in transitively. It is already on most classpaths.
- Spring Security is an optional dependency, needed only for `io.nobleson.jwt.spring.JwtService`. Any Spring Boot app already provides it, and non-Spring users never pull it in.

## Roadmap

A few things are planned for later releases:

- Encrypted tokens (JWE).
- JWK and JWKS parsing, including remote key sets.
- RSA-PSS (`PS256`, `PS384`, `PS512`).

## License

Apache License 2.0.
