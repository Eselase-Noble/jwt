/*
 * Nobleson JWT
 * https://github.com/Eselase-Noble/jwt
 *
 * Author:  Noble Eselase Vulley
 * Version: 0.2.0
 * Date:    2026-10-02
 */
package io.nobleson.jwt;

import io.nobleson.jwt.algorithm.Algorithm;
import io.nobleson.jwt.exception.ExpiredJwtException;
import io.nobleson.jwt.exception.InvalidClaimException;
import io.nobleson.jwt.exception.MalformedJwtException;
import io.nobleson.jwt.exception.PrematureJwtException;
import io.nobleson.jwt.exception.SignatureException;
import io.nobleson.jwt.internal.Base64Url;
import io.nobleson.jwt.internal.Json;
import io.nobleson.jwt.jwk.Jwk;
import io.nobleson.jwt.jwk.JwkProvider;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;

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
    private JwkProvider jwkProvider;
    private Set<String> permittedAlgorithms;
    private Duration clockSkew = Duration.ZERO;
    private final Map<String, Object> requiredClaims = new LinkedHashMap<>();
    private final List<Predicate<Jwt>> checks = new ArrayList<>();

    JwtParser() {
    }

    /** The algorithm (and key) the token's signature must verify against. Required unless using a {@link JwkProvider}. */
    public JwtParser verifyWith(Algorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    /**
     * Verify using a {@link JwkProvider}: the key is chosen by the token's {@code kid}
     * header, which is how OIDC providers and rotating-key setups work. The algorithm is
     * derived from the token's {@code alg} but constrained to what the resolved key
     * supports, so a token cannot force an incompatible algorithm. Combine with
     * {@link #permittedAlgorithms(String...)} to pin the acceptable set.
     */
    public JwtParser verifyWith(JwkProvider jwkProvider) {
        this.jwkProvider = jwkProvider;
        return this;
    }

    /** Restrict which {@code alg} values are acceptable (defense in depth). */
    public JwtParser permittedAlgorithms(String... algorithms) {
        this.permittedAlgorithms = Set.of(algorithms);
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
     * Add a custom check that runs after signature and claim validation. If the
     * predicate returns {@code false}, {@code parse} throws {@link InvalidClaimException}.
     * This is the extension point for things like a revocation/denylist lookup:
     *
     * <pre>{@code
     * Nobleson.parser()
     *         .verifyWith(algorithm)
     *         .check(jwt -> !denylist.isRevoked(jwt.claims().id()))
     *         .parse(token);
     * }</pre>
     *
     * You can add more than one check; they all have to pass.
     */
    public JwtParser check(Predicate<Jwt> check) {
        checks.add(Objects.requireNonNull(check, "check"));
        return this;
    }

    /**
     * Verify and parse without throwing: {@code true} if {@code token} is a valid,
     * unexpired, correctly signed JWT that meets every configured requirement.
     * Handy when you only need a yes/no answer and don't want a try/catch.
     */
    public boolean isValid(String token) {
        try {
            parse(token);
            return true;
        } catch (io.nobleson.jwt.exception.JwtException e) {
            return false;
        }
    }

    /**
     * Verify and parse {@code token}. Returns a {@link Jwt} whose signature and
     * time claims are already validated.
     */
    public Jwt parse(String token) {
        if (algorithm == null && jwkProvider == null) {
            throw new IllegalStateException("No verifier set — call verifyWith(...) before parse()");
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

        String headerAlg = headerMap.get(Header.ALGORITHM) == null
                ? null : headerMap.get(Header.ALGORITHM).toString();
        if (permittedAlgorithms != null && !permittedAlgorithms.contains(headerAlg)) {
            throw new SignatureException("Token alg '" + headerAlg + "' is not in the permitted set");
        }

        // Establish the verifier. Either a fixed algorithm, or one resolved from the
        // JWKS by the token's kid and constrained to that key's type.
        Algorithm verifier = resolveVerifier(headerMap, headerAlg);

        // Reject algorithm confusion: the header alg must be the one we verify with.
        if (!verifier.name().equals(headerAlg)) {
            throw new SignatureException("Token alg '" + headerAlg
                    + "' does not match the expected algorithm '" + verifier.name() + "'");
        }

        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        if (!verifier.verify(signingInput, signature)) {
            throw new SignatureException("JWT signature does not match");
        }

        Header header = new Header(headerMap);
        Claims claims = new Claims(claimsMap);

        validateTime(claims);
        validateRequiredClaims(claims);

        Jwt jwt = new Jwt(header, claims, token);
        for (Predicate<Jwt> check : checks) {
            if (!check.test(jwt)) {
                throw new InvalidClaimException("Token failed a custom validation check");
            }
        }
        return jwt;
    }

    private Algorithm resolveVerifier(Map<String, Object> headerMap, String headerAlg) {
        if (jwkProvider == null) {
            return algorithm;
        }
        String kid = headerMap.get(Header.KEY_ID) == null
                ? null : headerMap.get(Header.KEY_ID).toString();
        Jwk jwk = jwkProvider.get(kid);
        if (jwk == null) {
            throw new SignatureException("No JWK found for kid '" + kid + "'");
        }
        // Throws if the token's alg is incompatible with this key (e.g. HS256 or none
        // against an RSA key), which blocks a token from dictating the algorithm.
        return jwk.algorithmFor(headerAlg);
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
