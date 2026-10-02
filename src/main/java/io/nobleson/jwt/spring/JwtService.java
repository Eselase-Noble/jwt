/*
 * Nobleson JWT
 * https://github.com/Eselase-Noble/jwt
 *
 * Author:  Noble Eselase Vulley
 * Version: 0.1.0
 * Date:    2026-10-02
 */
package io.nobleson.jwt.spring;

import io.nobleson.jwt.Claims;
import io.nobleson.jwt.Jwt;
import io.nobleson.jwt.JwtBuilder;
import io.nobleson.jwt.Nobleson;
import io.nobleson.jwt.algorithm.Algorithm;
import io.nobleson.jwt.exception.ExpiredJwtException;
import io.nobleson.jwt.exception.JwtException;
import io.nobleson.jwt.exception.RevokedJwtException;
import io.nobleson.jwt.revocation.TokenDenylist;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
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
 * // In your filter (works for Bearer header or cookie, whichever you configured):
 * String token = jwtService.resolveToken(
 *         request.getHeader("Authorization"), request.getHeader("Cookie"));
 * if (token != null && jwtService.validateToken(token)) {
 *     SecurityContextHolder.getContext().setAuthentication(jwtService.getAuthentication(token));
 * }
 * }</pre>
 *
 * <p>By default the token is read from the {@code Authorization: Bearer} header. Call
 * {@link #tokenSource(TokenSource)} to read it from a cookie instead, and
 * {@link #cookieName(String)} to set the cookie name.</p>
 *
 * <p>This class is the only part of Nobleson that touches Spring. Spring Security
 * is an <em>optional</em> dependency of the library, present automatically in any
 * Spring Boot app and absent for everyone else.
 */
public class JwtService {

    /** Claim that carries the user's authorities (roles). */
    public static final String ROLES_CLAIM = "roles";

    /** Claims the service manages itself, so they are not copied over on refresh. */
    private static final Set<String> MANAGED_CLAIMS = Set.of(
            Claims.SUBJECT, Claims.EXPIRATION, Claims.NOT_BEFORE,
            Claims.ISSUED_AT, Claims.JWT_ID, ROLES_CLAIM);

    /** Default cookie name used when the token source is {@link TokenSource#COOKIE}. */
    public static final String DEFAULT_COOKIE_NAME = "accessToken";

    // protected so subclasses can read them when overriding behaviour.
    protected final Algorithm algorithm;
    protected final Duration tokenValidity;

    protected TokenSource tokenSource = TokenSource.BEARER;
    protected String cookieName = DEFAULT_COOKIE_NAME;
    protected TokenDenylist denylist;

    /** Use a one-hour token lifetime. */
    public JwtService(Algorithm algorithm) {
        this(algorithm, Duration.ofHours(1));
    }

    public JwtService(Algorithm algorithm, Duration tokenValidity) {
        this.algorithm = algorithm;
        this.tokenValidity = tokenValidity;
    }

    // ---------- configuration ----------

    /** Choose where incoming tokens are read from. Defaults to {@link TokenSource#BEARER}. Returns {@code this}. */
    public JwtService tokenSource(TokenSource source) {
        this.tokenSource = source;
        return this;
    }

    /** Set the cookie name used when the source is {@link TokenSource#COOKIE}. Returns {@code this}. */
    public JwtService cookieName(String cookieName) {
        this.cookieName = cookieName;
        return this;
    }

    /**
     * Attach a {@link TokenDenylist} so tokens can be revoked before they expire
     * (this is what makes {@link #revoke(String)} and {@link #logout(String)} work,
     * and what causes {@link #verify(String)} to reject a revoked token). Returns {@code this}.
     */
    public JwtService denylist(TokenDenylist denylist) {
        this.denylist = denylist;
        return this;
    }

    public TokenSource tokenSource() {
        return tokenSource;
    }

    public String cookieName() {
        return cookieName;
    }

    // ---------- issuing ----------

    /** Generate a signed token for the given user, carrying their authorities as the {@code roles} claim. */
    public String generateToken(UserDetails userDetails) {
        return generateToken(Map.of(), userDetails);
    }

    /** Generate a token with additional custom claims merged in alongside the standard ones. */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        JwtBuilder builder = Nobleson.builder()
                .id(UUID.randomUUID().toString())   // jti, so the token can be revoked later
                .subject(userDetails.getUsername())
                .claim(ROLES_CLAIM, userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList())
                .issuedNow()
                .expiresIn(tokenValidity);

        extraClaims.forEach(builder::claim);
        return builder.signWith(algorithm).generate();
    }

    /**
     * Re-issue a still-valid token with a fresh issue time and expiry, keeping the
     * subject, roles, and any custom claims. Throws if the token can no longer be
     * trusted (expired, tampered, wrong signature).
     */
    public String refreshToken(String token) {
        Jwt current = verify(token);

        JwtBuilder builder = Nobleson.builder()
                .id(UUID.randomUUID().toString())   // a fresh jti for the new token
                .subject(current.subject())
                .claim(ROLES_CLAIM, rolesOf(current))
                .issuedNow()
                .expiresIn(tokenValidity);

        current.claims().asMap().forEach((name, value) -> {
            if (!MANAGED_CLAIMS.contains(name)) {
                builder.claim(name, value);
            }
        });
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

    /** The token's issue time ({@code iat}), or {@code null} if absent. */
    public Instant extractIssuedAt(String token) {
        return extractClaim(token, Claims::issuedAt);
    }

    /** The token's id ({@code jti}), or {@code null} if absent. */
    public String extractTokenId(String token) {
        return extractClaim(token, Claims::id);
    }

    /** The token's issuer ({@code iss}), or {@code null} if absent. */
    public String extractIssuer(String token) {
        return extractClaim(token, Claims::issuer);
    }

    /** The roles stored in the token, or an empty list if none. */
    public List<String> extractRoles(String token) {
        return rolesOf(verify(token));
    }

    /** The roles stored in the token as Spring {@link GrantedAuthority} instances. */
    public Collection<? extends GrantedAuthority> extractAuthorities(String token) {
        return extractRoles(token).stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
    }

    /** Every claim in the token as a plain map. */
    public Map<String, Object> extractAllClaims(String token) {
        return verify(token).claims().asMap();
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
     * {@code true} if the token verifies and is unexpired. Never throws, so it is
     * safe to call directly in a filter or guard clause.
     */
    public boolean validateToken(String token) {
        try {
            verify(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    /**
     * {@code true} if the token verifies, is unexpired, and belongs to this user.
     * Never throws; a bad token simply returns {@code false}.
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            return userDetails.getUsername().equals(verify(token).subject());
        } catch (JwtException e) {
            return false;
        }
    }

    /**
     * {@code true} if the token is past its expiry, or cannot be trusted at all.
     * A missing {@code exp} is treated as not expired.
     */
    public boolean isTokenExpired(String token) {
        try {
            Instant exp = verify(token).claims().expiration();
            return exp != null && exp.isBefore(Instant.now());
        } catch (ExpiredJwtException e) {
            return true;
        } catch (JwtException e) {
            return true;
        }
    }

    /** How long until the token expires, clamped at zero. {@code null} if it has no expiry. */
    public Duration getRemainingValidity(String token) {
        Instant exp = extractExpiration(token);
        if (exp == null) {
            return null;
        }
        Duration remaining = Duration.between(Instant.now(), exp);
        return remaining.isNegative() ? Duration.ZERO : remaining;
    }

    // ---------- Spring integration ----------

    /**
     * Build a Spring {@link Authentication} straight from a token: the principal is
     * the username and the authorities come from the {@code roles} claim. Drop it
     * into {@code SecurityContextHolder} in your filter. Throws if the token is invalid.
     */
    public Authentication getAuthentication(String token) {
        Jwt jwt = verify(token);
        List<SimpleGrantedAuthority> authorities = rolesOf(jwt).stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
        return new UsernamePasswordAuthenticationToken(jwt.subject(), null, authorities);
    }

    /**
     * Verify signature and time claims (and, if a denylist is configured, that the
     * token has not been revoked) and return the parsed token. Throws on any problem.
     */
    public Jwt verify(String token) {
        Jwt jwt = Nobleson.parser().verifyWith(algorithm).parse(token);
        if (denylist != null) {
            String id = jwt.claims().id();
            if (id != null && denylist.isRevoked(id)) {
                throw new RevokedJwtException("Token has been revoked");
            }
        }
        return jwt;
    }

    // ---------- revocation (logout) ----------

    /**
     * Revoke a token so it stops being accepted, even though it has not expired. Its
     * {@code jti} is placed on the configured {@link TokenDenylist} until it would have
     * expired. A token with no denylist, no {@code jti}, or one that is already expired
     * is a no-op. Requires {@link #denylist(TokenDenylist)} to have been set.
     */
    public void revoke(String token) {
        if (denylist == null) {
            throw new IllegalStateException("No TokenDenylist configured; call denylist(...) first");
        }
        try {
            Jwt jwt = Nobleson.parser().verifyWith(algorithm).parse(token);
            denylist.revoke(jwt.claims().id(), jwt.claims().expiration());
        } catch (ExpiredJwtException e) {
            // Already expired, so it is rejected anyway; nothing to revoke.
        }
    }

    /** Log a user out by revoking their token. Alias for {@link #revoke(String)}. */
    public void logout(String token) {
        revoke(token);
    }

    // ---------- token resolution (Bearer or cookie) ----------

    /**
     * Pull the token off a request using the configured {@link TokenSource}. Pass the
     * two header values your filter already has; the unused one may be {@code null}.
     * Returns {@code null} when no token is present.
     *
     * <pre>{@code
     * String token = jwtService.resolveToken(
     *         request.getHeader("Authorization"),   // for BEARER
     *         request.getHeader("Cookie"));         // for COOKIE
     * }</pre>
     */
    public String resolveToken(String authorizationHeader, String cookieHeader) {
        return tokenSource == TokenSource.COOKIE
                ? extractCookieToken(cookieHeader, cookieName)
                : extractBearerToken(authorizationHeader);
    }

    /**
     * Build a {@code Set-Cookie} header value that stores the token in the configured
     * cookie, hardened with {@code HttpOnly}, {@code Secure}, {@code SameSite=Strict},
     * {@code Path=/}, and a {@code Max-Age} matching the token lifetime. Add it to your
     * login response: {@code response.addHeader("Set-Cookie", jwtService.buildCookie(token))}.
     */
    public String buildCookie(String token) {
        return cookieName + "=" + token
                + "; Max-Age=" + tokenValidity.getSeconds()
                + "; Path=/; HttpOnly; Secure; SameSite=Strict";
    }

    /** Build a {@code Set-Cookie} header value that immediately clears the token cookie, for logout. */
    public String buildClearCookie() {
        return cookieName + "=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict";
    }

    // ---------- static helpers ----------

    /**
     * Pull the raw token out of an {@code Authorization} header value, stripping the
     * {@code "Bearer "} prefix. Returns {@code null} if the header is missing or not a
     * bearer token. Static and servlet-free, so it works the same on any framework.
     */
    public static String extractBearerToken(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7).trim();
            return token.isEmpty() ? null : token;
        }
        return null;
    }

    /**
     * Pull a named cookie's value out of a raw {@code Cookie} request-header string
     * (e.g. {@code "theme=dark; accessToken=eyJ..."}). Returns {@code null} if absent.
     * Static and servlet-free, so it works with both {@code javax} and {@code jakarta}.
     */
    public static String extractCookieToken(String cookieHeader, String cookieName) {
        if (cookieHeader == null || cookieName == null) {
            return null;
        }
        for (String part : cookieHeader.split(";")) {
            String pair = part.trim();
            int eq = pair.indexOf('=');
            if (eq > 0 && pair.substring(0, eq).trim().equals(cookieName)) {
                String value = pair.substring(eq + 1).trim();
                return value.isEmpty() ? null : value;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    protected List<String> rolesOf(Jwt jwt) {
        Object roles = jwt.claims().get(ROLES_CLAIM);
        if (roles instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return List.of();
    }
}
