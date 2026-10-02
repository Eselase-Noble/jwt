package io.nobleson.jwt;

import io.nobleson.jwt.algorithm.Algorithm;
import io.nobleson.jwt.exception.JwtException;
import io.nobleson.jwt.internal.Base64Url;
import io.nobleson.jwt.internal.Json;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Fluent builder for creating and signing a JWT. Set claims, choose how to sign
 * with {@link #signWith(Algorithm)}, then call {@link #generate()} to get the
 * compact token string.
 *
 * <pre>{@code
 * String token = Nobleson.builder()
 *         .subject("user-123")
 *         .issuer("my-app")
 *         .claim("role", "admin")
 *         .issuedNow()
 *         .expiresIn(Duration.ofHours(1))
 *         .signWith(Algorithms.hs256(secret))
 *         .generate();
 * }</pre>
 */
public final class JwtBuilder {

    private final Map<String, Object> header = new LinkedHashMap<>();
    private final Map<String, Object> claims = new LinkedHashMap<>();
    private Algorithm algorithm;

    JwtBuilder() {
        header.put(Header.TYPE, "JWT");
    }

    // ---- registered claims ----

    public JwtBuilder issuer(String issuer) {
        return claim(Claims.ISSUER, issuer);
    }

    public JwtBuilder subject(String subject) {
        return claim(Claims.SUBJECT, subject);
    }

    public JwtBuilder audience(String audience) {
        return claim(Claims.AUDIENCE, audience);
    }

    public JwtBuilder id(String id) {
        return claim(Claims.JWT_ID, id);
    }

    public JwtBuilder expiration(Instant exp) {
        return claim(Claims.EXPIRATION, exp.getEpochSecond());
    }

    public JwtBuilder notBefore(Instant nbf) {
        return claim(Claims.NOT_BEFORE, nbf.getEpochSecond());
    }

    public JwtBuilder issuedAt(Instant iat) {
        return claim(Claims.ISSUED_AT, iat.getEpochSecond());
    }

    /** Set {@code iat} to the current time. */
    public JwtBuilder issuedNow() {
        return issuedAt(Instant.now());
    }

    /** Set {@code exp} to {@code now + ttl}. */
    public JwtBuilder expiresIn(Duration ttl) {
        return expiration(Instant.now().plus(ttl));
    }

    // ---- arbitrary claims & header fields ----

    /** Add or overwrite a custom claim. A {@code null} value removes the claim. */
    public JwtBuilder claim(String name, Object value) {
        if (value == null) {
            claims.remove(name);
        } else {
            claims.put(name, value);
        }
        return this;
    }

    /** Set the {@code kid} (key id) header. */
    public JwtBuilder keyId(String kid) {
        header.put(Header.KEY_ID, kid);
        return this;
    }

    /** Set an arbitrary JOSE header field. */
    public JwtBuilder headerField(String name, Object value) {
        header.put(name, value);
        return this;
    }

    // ---- signing ----

    /** Choose the algorithm (and key) to sign with. Required before {@link #generate()}. */
    public JwtBuilder signWith(Algorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    /**
     * Serialize and sign the token, returning its compact form
     * {@code base64url(header).base64url(payload).base64url(signature)}.
     */
    public String generate() {
        if (algorithm == null) {
            throw new JwtException("No algorithm set — call signWith(...) before generate()");
        }
        header.put(Header.ALGORITHM, algorithm.name());

        String encodedHeader = Base64Url.encode(Json.write(header));
        String encodedPayload = Base64Url.encode(Json.write(claims));
        String signingInput = encodedHeader + "." + encodedPayload;

        byte[] signature = algorithm.sign(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + Base64Url.encode(signature);
    }
}
