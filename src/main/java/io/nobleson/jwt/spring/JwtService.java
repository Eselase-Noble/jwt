package io.nobleson.jwt.spring;

import io.nobleson.jwt.Claims;
import io.nobleson.jwt.Jwt;
import io.nobleson.jwt.Nobleson;
import io.nobleson.jwt.algorithm.Algorithm;
import io.nobleson.jwt.exception.JwtException;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.function.Function;

/**
 * Drop-in JWT service for Spring Security. It speaks {@link UserDetails}, so it
 * slots straight into the usual authentication flow with no boilerplate:
 *
 * <pre>{@code
 * // Register it once (secret/key from your config):
 * @Bean
 * JwtService jwtService(@Value("${app.jwt.secret}") String secret) {
 *     return new JwtService(Algorithms.hs256(secret), Duration.ofHours(1));
 * }
 *
 * // Issue a token after a successful login:
 * String token = jwtService.generateToken(userDetails);
 *
 * // In your filter:
 * String username = jwtService.extractUsername(token);
 * if (jwtService.isTokenValid(token, userDetails)) { ... authenticate ... }
 * }</pre>
 *
 * <p>This class is the only part of Nobleson that touches Spring. Spring Security
 * is an <em>optional</em> dependency of the library — present automatically in any
 * Spring Boot app, absent for everyone else.
 */
public class JwtService {

    /** Claim that carries the user's authorities (roles). */
    public static final String ROLES_CLAIM = "roles";

    private final Algorithm algorithm;
    private final Duration tokenValidity;

    /** Use a one-hour token lifetime. */
    public JwtService(Algorithm algorithm) {
        this(algorithm, Duration.ofHours(1));
    }

    public JwtService(Algorithm algorithm, Duration tokenValidity) {
        this.algorithm = algorithm;
        this.tokenValidity = tokenValidity;
    }

    // ---------- issuing ----------

    /** Generate a signed token for the given user, carrying their authorities as the {@code roles} claim. */
    public String generateToken(UserDetails userDetails) {
        return generateToken(Map.of(), userDetails);
    }

    /** Generate a token with additional custom claims merged in alongside the standard ones. */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        var builder = Nobleson.builder()
                .subject(userDetails.getUsername())
                .claim(ROLES_CLAIM, userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList())
                .issuedNow()
                .expiresIn(tokenValidity);

        extraClaims.forEach(builder::claim);
        return builder.signWith(algorithm).generate();
    }

    // ---------- reading ----------

    /** The username ({@code sub}) carried by the token. Throws if the token is invalid or expired. */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::subject);
    }

    /** The token's expiry, or {@code null} if it has none. */
    public Instant extractExpiration(String token) {
        return extractClaim(token, Claims::expiration);
    }

    /**
     * Pull any value out of a verified token, e.g.
     * {@code extractClaim(token, c -> c.get("email", String.class))}.
     * The token's signature and expiry are checked first.
     */
    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        return resolver.apply(verify(token).claims());
    }

    // ---------- validating ----------

    /**
     * {@code true} if the token verifies, is unexpired, and belongs to this user.
     * Never throws — a bad token simply returns {@code false}.
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            // verify() already enforces signature and expiry; just confirm the subject.
            return userDetails.getUsername().equals(verify(token).subject());
        } catch (JwtException e) {
            return false;
        }
    }

    /** {@code true} if the token verifies and is unexpired, regardless of which user it is. */
    public boolean isTokenValid(String token) {
        try {
            verify(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    /** Verify signature + time claims and return the parsed token (throws on any problem). */
    public Jwt verify(String token) {
        return Nobleson.parser().verifyWith(algorithm).parse(token);
    }
}
