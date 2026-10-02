/*
 * Nobleson JWT
 * https://github.com/Eselase-Noble/jwt
 *
 * Author:  Noble Eselase Vulley
 * Version: 0.1.0
 * Date:    2026-10-02
 */
package io.nobleson.jwt;

import io.nobleson.jwt.algorithm.Algorithm;
import io.nobleson.jwt.algorithm.Algorithms;
import io.nobleson.jwt.exception.SignatureException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HmacTest {

    // At least 64 bytes so the same secret satisfies HS256, HS384, and HS512.
    private static final String SECRET =
            "a-very-long-and-secure-shared-secret-key-that-is-at-least-64-bytes-long";

    @Test
    void roundTripHs256() {
        String token = Nobleson.builder()
                .subject("user-123")
                .issuer("my-app")
                .claim("role", "admin")
                .signWith(Algorithms.hs256(SECRET))
                .generate();

        Jwt jwt = Nobleson.parser()
                .verifyWith(Algorithms.hs256(SECRET))
                .parse(token);

        assertEquals("user-123", jwt.subject());
        assertEquals("my-app", jwt.issuer());
        assertEquals("admin", jwt.claims().get("role", String.class));
    }

    @Test
    void roundTripAllHmacVariants() {
        for (Algorithm[] pair : new Algorithm[][]{
                {Algorithms.hs256(SECRET), Algorithms.hs256(SECRET)},
                {Algorithms.hs384(SECRET), Algorithms.hs384(SECRET)},
                {Algorithms.hs512(SECRET), Algorithms.hs512(SECRET)},
        }) {
            String token = Nobleson.builder().subject("s").signWith(pair[0]).generate();
            Jwt jwt = Nobleson.parser().verifyWith(pair[1]).parse(token);
            assertEquals("s", jwt.subject());
        }
    }

    @Test
    void tamperedTokenIsRejected() {
        String token = Nobleson.builder().subject("user").signWith(Algorithms.hs256(SECRET)).generate();
        // Flip a character in the signature segment: well-formed, but no longer a match.
        String[] parts = token.split("\\.");
        char[] sig = parts[2].toCharArray();
        sig[0] = sig[0] == 'A' ? 'B' : 'A';
        String tampered = parts[0] + "." + parts[1] + "." + new String(sig);

        assertThrows(SignatureException.class,
                () -> Nobleson.parser().verifyWith(Algorithms.hs256(SECRET)).parse(tampered));
    }

    @Test
    void wrongSecretIsRejected() {
        String token = Nobleson.builder().subject("user").signWith(Algorithms.hs256(SECRET)).generate();
        String wrongButLongEnough = "a-different-secret-entirely-that-is-also-at-least-32-bytes";
        assertThrows(SignatureException.class,
                () -> Nobleson.parser().verifyWith(Algorithms.hs256(wrongButLongEnough)).parse(token));
    }

    @Test
    void producesThreePartToken() {
        String token = Nobleson.builder().subject("user").signWith(Algorithms.hs256(SECRET)).generate();
        assertTrue(token.chars().filter(c -> c == '.').count() == 2, "token should have 3 parts");
    }
}
