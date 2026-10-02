package io.nobleson.jwt;

import io.nobleson.jwt.algorithm.Algorithms;
import io.nobleson.jwt.exception.ExpiredJwtException;
import io.nobleson.jwt.exception.InvalidClaimException;
import io.nobleson.jwt.exception.MalformedJwtException;
import io.nobleson.jwt.exception.PrematureJwtException;
import io.nobleson.jwt.exception.SignatureException;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ValidationTest {

    private static final String SECRET = "a-very-long-and-secure-shared-secret-key";

    @Test
    void expiredTokenRejected() {
        String token = Nobleson.builder()
                .subject("user")
                .expiration(Instant.now().minusSeconds(60))
                .signWith(Algorithms.hs256(SECRET))
                .generate();

        assertThrows(ExpiredJwtException.class,
                () -> Nobleson.parser().verifyWith(Algorithms.hs256(SECRET)).parse(token));
    }

    @Test
    void expiredWithinClockSkewAccepted() {
        String token = Nobleson.builder()
                .subject("user")
                .expiration(Instant.now().minusSeconds(10))
                .signWith(Algorithms.hs256(SECRET))
                .generate();

        assertDoesNotThrow(() -> Nobleson.parser()
                .verifyWith(Algorithms.hs256(SECRET))
                .clockSkew(Duration.ofSeconds(30))
                .parse(token));
    }

    @Test
    void notYetValidTokenRejected() {
        String token = Nobleson.builder()
                .subject("user")
                .notBefore(Instant.now().plusSeconds(60))
                .signWith(Algorithms.hs256(SECRET))
                .generate();

        assertThrows(PrematureJwtException.class,
                () -> Nobleson.parser().verifyWith(Algorithms.hs256(SECRET)).parse(token));
    }

    @Test
    void requiredIssuerMismatchRejected() {
        String token = Nobleson.builder()
                .issuer("attacker")
                .signWith(Algorithms.hs256(SECRET))
                .generate();

        assertThrows(InvalidClaimException.class, () -> Nobleson.parser()
                .verifyWith(Algorithms.hs256(SECRET))
                .requireIssuer("my-app")
                .parse(token));
    }

    @Test
    void requiredAudienceMatchAccepted() {
        String token = Nobleson.builder()
                .audience("my-api")
                .signWith(Algorithms.hs256(SECRET))
                .generate();

        Jwt jwt = Nobleson.parser()
                .verifyWith(Algorithms.hs256(SECRET))
                .requireAudience("my-api")
                .parse(token);
        assertEquals("my-api", jwt.audience());
    }

    @Test
    void missingRequiredClaimRejected() {
        String token = Nobleson.builder().signWith(Algorithms.hs256(SECRET)).generate();
        assertThrows(InvalidClaimException.class, () -> Nobleson.parser()
                .verifyWith(Algorithms.hs256(SECRET))
                .requireIssuer("my-app")
                .parse(token));
    }

    @Test
    void malformedTokensRejected() {
        var parser = Nobleson.parser().verifyWith(Algorithms.hs256(SECRET));
        assertThrows(MalformedJwtException.class, () -> parser.parse("only.two"));
        assertThrows(MalformedJwtException.class, () -> parser.parse("a.b.c.d"));
        assertThrows(MalformedJwtException.class, () -> parser.parse("!!!.!!!.!!!"));
    }

    @Test
    void algConfusionRejected() {
        // Signed with HMAC, but the verifier expects RSA — must be rejected, not misverified.
        String hmacToken = Nobleson.builder()
                .subject("user")
                .signWith(Algorithms.hs256(SECRET))
                .generate();

        KeyPair rsa = Keys.rsaKeyPair();
        assertThrows(SignatureException.class,
                () -> Nobleson.parser().verifyWith(Algorithms.rs256(rsa.getPublic())).parse(hmacToken));
    }
}
