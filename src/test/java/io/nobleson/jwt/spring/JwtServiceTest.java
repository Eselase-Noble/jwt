package io.nobleson.jwt.spring;

import io.nobleson.jwt.algorithm.Algorithms;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
}
