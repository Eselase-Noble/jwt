/*
 * Nobleson JWT
 * https://github.com/Eselase-Noble/jwt
 *
 * Author:  Noble Eselase Vulley
 * Version: 0.1.0
 * Date:    2026-10-02
 */
package io.nobleson.jwt.spring;

import io.nobleson.jwt.algorithm.Algorithms;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtServiceTest {

    private static final String SECRET = "a-very-long-and-secure-shared-secret-key";
    private final JwtService service = new JwtService(Algorithms.hs256(SECRET));

    private UserDetails user(String name, String... roles) {
        return User.withUsername(name).password("x").authorities(roles).build();
    }

    @Test
    void generateThenExtractUsername() {
        UserDetails bob = user("bob", "ROLE_ADMIN");
        String token = service.generateToken(bob);
        assertEquals("bob", service.extractUsername(token));
    }

    @Test
    void tokenCarriesAuthoritiesAsRolesClaim() {
        String token = service.generateToken(user("bob", "ROLE_ADMIN", "ROLE_USER"));
        @SuppressWarnings("unchecked")
        List<String> roles = service.extractClaim(token, c -> c.get(JwtService.ROLES_CLAIM, List.class));
        assertTrue(roles.contains("ROLE_ADMIN"));
        assertTrue(roles.contains("ROLE_USER"));
    }

    @Test
    void extraClaimsAreIncluded() {
        String token = service.generateToken(Map.of("email", "bob@example.com"), user("bob"));
        assertEquals("bob@example.com", service.extractClaim(token, c -> c.get("email", String.class)));
    }

    @Test
    void validForMatchingUser() {
        UserDetails bob = user("bob", "ROLE_USER");
        String token = service.generateToken(bob);
        assertTrue(service.isTokenValid(token, bob));
    }

    @Test
    void invalidForDifferentUser() {
        String token = service.generateToken(user("bob", "ROLE_USER"));
        assertFalse(service.isTokenValid(token, user("alice", "ROLE_USER")));
    }

    @Test
    void invalidForExpiredToken() {
        JwtService shortLived = new JwtService(Algorithms.hs256(SECRET), Duration.ofSeconds(-1));
        UserDetails bob = user("bob");
        String token = shortLived.generateToken(bob);
        assertFalse(shortLived.isTokenValid(token, bob));
    }

    @Test
    void invalidForGarbageToken() {
        assertFalse(service.isTokenValid("not.a.token", user("bob")));
    }

    @Test
    void validateTokenBoolean() {
        String token = service.generateToken(user("bob"));
        assertTrue(service.validateToken(token));
        assertFalse(service.validateToken("garbage"));
        assertFalse(service.validateToken(null));
    }

    @Test
    void isTokenExpired() {
        assertFalse(service.isTokenExpired(service.generateToken(user("bob"))));

        JwtService shortLived = new JwtService(Algorithms.hs256(SECRET), Duration.ofSeconds(-1));
        assertTrue(shortLived.isTokenExpired(shortLived.generateToken(user("bob"))));
        assertTrue(service.isTokenExpired("garbage"));
    }

    @Test
    void remainingValidity() {
        String token = service.generateToken(user("bob"));
        Duration remaining = service.getRemainingValidity(token);
        assertTrue(remaining.toMinutes() > 55 && remaining.toMinutes() <= 60);
    }

    @Test
    void extractRolesAndAuthorities() {
        String token = service.generateToken(user("bob", "ROLE_ADMIN", "ROLE_USER"));
        assertTrue(service.extractRoles(token).contains("ROLE_ADMIN"));
        assertTrue(service.extractAuthorities(token).stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
    }

    @Test
    void getAuthenticationCarriesPrincipalAndAuthorities() {
        String token = service.generateToken(user("bob", "ROLE_ADMIN"));
        Authentication auth = service.getAuthentication(token);
        assertEquals("bob", auth.getName());
        assertTrue(auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
    }

    @Test
    void refreshKeepsSubjectRolesAndCustomClaims() {
        String original = service.generateToken(Map.of("tenant", "acme"), user("bob", "ROLE_USER"));
        String refreshed = service.refreshToken(original);

        assertEquals("bob", service.extractUsername(refreshed));
        assertTrue(service.extractRoles(refreshed).contains("ROLE_USER"));
        assertEquals("acme", service.extractClaim(refreshed, c -> c.get("tenant", String.class)));
    }

    @Test
    void extractClaimReaders() {
        String token = service.generateToken(user("bob"));
        assertTrue(service.extractAllClaims(token).containsKey("sub"));
        // iat is set by issuedNow(); exp by the lifetime.
        assertTrue(service.extractIssuedAt(token) != null);
        assertTrue(service.extractExpiration(token) != null);
    }

    @Test
    void extractBearerToken() {
        assertEquals("abc.def.ghi", JwtService.extractBearerToken("Bearer abc.def.ghi"));
        assertNull(JwtService.extractBearerToken("Basic abc"));
        assertNull(JwtService.extractBearerToken(null));
    }

    @Test
    void extractCookieToken() {
        String header = "theme=dark; accessToken=abc.def.ghi; locale=en";
        assertEquals("abc.def.ghi", JwtService.extractCookieToken(header, "accessToken"));
        assertNull(JwtService.extractCookieToken(header, "missing"));
        assertNull(JwtService.extractCookieToken(null, "accessToken"));
    }

    @Test
    void resolveTokenDefaultsToBearer() {
        String token = service.generateToken(user("bob"));
        // Default source is BEARER: reads the Authorization header, ignores the cookie.
        assertEquals(token, service.resolveToken("Bearer " + token, "accessToken=other"));
        assertNull(service.resolveToken(null, "accessToken=" + token));
    }

    @Test
    void resolveTokenFromCookieWhenConfigured() {
        JwtService cookieService = new JwtService(Algorithms.hs256(SECRET))
                .tokenSource(TokenSource.COOKIE)
                .cookieName("jwt");
        String token = cookieService.generateToken(user("bob"));

        assertEquals(token, cookieService.resolveToken("Bearer ignored", "jwt=" + token));
        assertNull(cookieService.resolveToken("Bearer " + token, null));
    }

    @Test
    void buildAndClearCookie() {
        String token = service.generateToken(user("bob"));
        String setCookie = service.buildCookie(token);
        assertTrue(setCookie.startsWith("accessToken=" + token));
        assertTrue(setCookie.contains("HttpOnly"));
        assertTrue(setCookie.contains("Secure"));
        assertTrue(setCookie.contains("Max-Age=3600"));

        assertTrue(service.buildClearCookie().contains("Max-Age=0"));
    }
}
