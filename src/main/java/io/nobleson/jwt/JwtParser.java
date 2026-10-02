package io.nobleson.jwt;

import io.nobleson.jwt.algorithm.Algorithm;
import io.nobleson.jwt.exception.ExpiredJwtException;
import io.nobleson.jwt.exception.InvalidClaimException;
import io.nobleson.jwt.exception.MalformedJwtException;
import io.nobleson.jwt.exception.PrematureJwtException;
import io.nobleson.jwt.exception.SignatureException;
import io.nobleson.jwt.internal.Base64Url;
import io.nobleson.jwt.internal.Json;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Fluent verifier and parser. Tell it how to verify with {@link #verifyWith(Algorithm)},
 * add any claim requirements, then call {@link #parse(String)}.
 *
 * <p>{@link #parse(String)} performs, in order: structural checks, an
 * algorithm-match check (the token's {@code alg} must equal the verifier's), a
 * signature check, {@code exp}/{@code nbf} time checks (with configurable clock
 * skew), and finally any {@code require...} claim expectations. Any failure throws
 * a specific {@link io.nobleson.jwt.exception.JwtException} subtype.
 */
public final class JwtParser {

    private Algorithm algorithm;
    private Duration clockSkew = Duration.ZERO;
    private final Map<String, Object> requiredClaims = new LinkedHashMap<>();

    JwtParser() {
    }

    /** The algorithm (and key) the token's signature must verify against. Required. */
    public JwtParser verifyWith(Algorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    /** Allowance for clock drift when checking {@code exp} and {@code nbf}. Default zero. */
    public JwtParser clockSkew(Duration clockSkew) {
        this.clockSkew = Objects.requireNonNull(clockSkew, "clockSkew");
        return this;
    }

    public JwtParser requireIssuer(String issuer) {
        return require(Claims.ISSUER, issuer);
    }

    public JwtParser requireAudience(String audience) {
        return require(Claims.AUDIENCE, audience);
    }

    public JwtParser requireSubject(String subject) {
        return require(Claims.SUBJECT, subject);
    }

    /** Require a claim to be present and equal to {@code value}. */
    public JwtParser require(String name, Object value) {
        requiredClaims.put(name, value);
        return this;
    }

    /**
     * Verify and parse {@code token}. Returns a {@link Jwt} whose signature and
     * time claims are already validated.
     */
    public Jwt parse(String token) {
        if (algorithm == null) {
            throw new IllegalStateException("No algorithm set — call verifyWith(...) before parse()");
        }
        if (token == null || token.isEmpty()) {
            throw new MalformedJwtException("Token is null or empty");
        }

        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new MalformedJwtException(
                    "Expected a token with 3 dot-separated parts but found " + parts.length);
        }

        Map<String, Object> headerMap = Json.readMap(Base64Url.decode(parts[0]));
        Map<String, Object> claimsMap = Json.readMap(Base64Url.decode(parts[1]));
        byte[] signature = Base64Url.decode(parts[2]);

        // Reject algorithm confusion: the header alg must be the one we verify with.
        Object headerAlg = headerMap.get(Header.ALGORITHM);
        if (!algorithm.name().equals(headerAlg)) {
            throw new SignatureException("Token alg '" + headerAlg
                    + "' does not match the expected algorithm '" + algorithm.name() + "'");
        }

        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        if (!algorithm.verify(signingInput, signature)) {
            throw new SignatureException("JWT signature does not match");
        }

        Header header = new Header(headerMap);
        Claims claims = new Claims(claimsMap);

        validateTime(claims);
        validateRequiredClaims(claims);

        return new Jwt(header, claims, token);
    }

    private void validateTime(Claims claims) {
        Instant now = Instant.now();

        Instant exp = claims.expiration();
        if (exp != null && now.isAfter(exp.plus(clockSkew))) {
            throw new ExpiredJwtException("Token expired at " + exp);
        }

        Instant nbf = claims.notBefore();
        if (nbf != null && now.isBefore(nbf.minus(clockSkew))) {
            throw new PrematureJwtException("Token not valid before " + nbf);
        }
    }

    private void validateRequiredClaims(Claims claims) {
        for (Map.Entry<String, Object> required : requiredClaims.entrySet()) {
            Object actual = claims.get(required.getKey());
            if (actual == null) {
                throw new InvalidClaimException("Missing required claim '" + required.getKey() + "'");
            }
            if (!actual.equals(required.getValue())) {
                throw new InvalidClaimException("Claim '" + required.getKey() + "' expected '"
                        + required.getValue() + "' but was '" + actual + "'");
            }
        }
    }
}
