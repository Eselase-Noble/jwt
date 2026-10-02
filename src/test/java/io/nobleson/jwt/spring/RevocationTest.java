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
import io.nobleson.jwt.revocation.InMemoryTokenDenylist;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RevocationTest {

    private static final String SECRET = "a-very-long-and-secure-shared-secret-key";

    private UserDetails user(String name, String... roles) {
        return User.withUsername(name).password("x").authorities(roles).build();
    }

    private JwtService serviceWithDenylist() {
        return new JwtService(Algorithms.hs256(SECRET))
                .denylist(new InMemoryTokenDenylist());
    }

    @Test
    void tokenValidUntilRevoked() {
        JwtService service = serviceWithDenylist();
        String token = service.generateToken(user("bob"));

        assertTrue(service.validateToken(token));

        service.logout(token);

        assertFalse(service.validateToken(token));
        assertFalse(service.isTokenValid(token, user("bob")));
    }

    @Test
    void verifyThrowsRevokedForRevokedToken() {
        JwtService service = serviceWithDenylist();
        String token = service.generateToken(user("bob"));
        service.revoke(token);

        assertThrows(io.nobleson.jwt.exception.RevokedJwtException.class, () -> service.verify(token));
    }

    @Test
    void revokingOneTokenDoesNotAffectAnother() {
        JwtService service = serviceWithDenylist();
        String a = service.generateToken(user("alice"));
        String b = service.generateToken(user("bob"));

        service.revoke(a);

        assertFalse(service.validateToken(a));
        assertTrue(service.validateToken(b));
    }

    @Test
    void revokeWithoutDenylistThrows() {
        JwtService noDenylist = new JwtService(Algorithms.hs256(SECRET));
        String token = noDenylist.generateToken(user("bob"));
        assertThrows(IllegalStateException.class, () -> noDenylist.revoke(token));
    }

    @Test
    void generatedTokensHaveUniqueIds() {
        JwtService service = new JwtService(Algorithms.hs256(SECRET));
        String id1 = service.extractTokenId(service.generateToken(user("bob")));
        String id2 = service.extractTokenId(service.generateToken(user("bob")));
        assertFalse(id1.equals(id2));
    }

    @Test
    void denylistForgetsExpiredEntries() {
        InMemoryTokenDenylist denylist = new InMemoryTokenDenylist();
        denylist.revoke("live", Instant.now().plus(Duration.ofMinutes(5)));
        denylist.revoke("stale", Instant.now().minusSeconds(1));

        assertTrue(denylist.isRevoked("live"));
        assertFalse(denylist.isRevoked("stale"));
        assertEquals(1, denylist.size());
    }
}
