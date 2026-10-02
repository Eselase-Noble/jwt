/*
 * Nobleson JWT
 * https://github.com/Eselase-Noble/jwt
 *
 * Author:  Noble Eselase Vulley
 * Version: 0.1.0
 * Date:    2026-10-02
 */
package io.nobleson.jwt;

import io.nobleson.jwt.algorithm.Algorithms;
import io.nobleson.jwt.exception.JwtException;
import io.nobleson.jwt.exception.SignatureException;
import io.nobleson.jwt.internal.Base64Url;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Adversarial tests covering the classic JWT attack classes. Each one asserts that
 * a crafted malicious token is rejected, so the library's defenses are evidence,
 * not inference.
 */
class SecurityTest {

    // 64+ bytes so it is a valid secret for every HMAC variant.
    private static final byte[] SECRET =
            "a-very-long-and-secure-shared-secret-key-that-is-at-least-64-bytes-long"
                    .getBytes(StandardCharsets.UTF_8);

    private static String encode(String json) {
        return Base64Url.encode(json.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * The "alg": "none" attack: a token that claims no signature. It must be rejected,
     * and there must be no way to produce one with the builder in the first place.
     */
    @Test
    void algNoneTokenIsRejected() {
        String header = encode("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        String payload = encode("{\"sub\":\"admin\"}");
        String noneToken = header + "." + payload + ".";

        assertThrows(JwtException.class,
                () -> Nobleson.parser().verifyWith(Algorithms.hs256(SECRET)).parse(noneToken));

        // There is also no API that would mint a none-signed token.
        assertFalse(Nobleson.parser().verifyWith(Algorithms.hs256(SECRET)).isValid(noneToken));
    }

    /**
     * The RS256 to HS256 algorithm-confusion attack. An attacker takes the server's
     * PUBLIC RSA key, uses its bytes as an HMAC secret, and signs a forged HS256 token.
     * If the server naively verified using the token's own alg, it would accept it.
     * Nobleson pins the expected algorithm, so the forgery is rejected.
     */
    @Test
    void rsaToHmacConfusionIsRejected() {
        KeyPair rsa = Keys.rsaKeyPair();
        byte[] publicKeyBytes = rsa.getPublic().getEncoded();

        // Attacker forges an HS256 token using the public key bytes as the HMAC secret.
        String forged = Nobleson.builder()
                .subject("attacker")
                .claim("role", "admin")
                .signWith(Algorithms.hs256(publicKeyBytes))
                .generate();

        // Server verifies as RS256 with its public key: must reject (alg mismatch).
        assertThrows(SignatureException.class,
                () -> Nobleson.parser().verifyWith(Algorithms.rs256(rsa.getPublic())).parse(forged));
    }

    /** Stripping the signature (empty third segment) must not verify. */
    @Test
    void strippedSignatureIsRejected() {
        String token = Nobleson.builder().subject("user").signWith(Algorithms.hs256(SECRET)).generate();
        String[] parts = token.split("\\.");
        String stripped = parts[0] + "." + parts[1] + ".";

        assertThrows(JwtException.class,
                () -> Nobleson.parser().verifyWith(Algorithms.hs256(SECRET)).parse(stripped));
    }

    /** Rewriting the header to claim a different algorithm must be rejected. */
    @Test
    void tamperedHeaderAlgorithmIsRejected() {
        String token = Nobleson.builder().subject("user").signWith(Algorithms.hs256(SECRET)).generate();
        String[] parts = token.split("\\.");

        String forgedHeader = encode("{\"alg\":\"HS512\",\"typ\":\"JWT\"}");
        String tampered = forgedHeader + "." + parts[1] + "." + parts[2];

        assertThrows(SignatureException.class,
                () -> Nobleson.parser().verifyWith(Algorithms.hs512(SECRET)).parse(tampered));
    }

    /** Editing a claim in the payload must invalidate the signature. */
    @Test
    void tamperedPayloadIsRejected() {
        String token = Nobleson.builder().subject("user").claim("role", "user")
                .signWith(Algorithms.hs256(SECRET)).generate();
        String[] parts = token.split("\\.");

        String forgedPayload = encode("{\"sub\":\"user\",\"role\":\"admin\"}");
        String tampered = parts[0] + "." + forgedPayload + "." + parts[2];

        assertThrows(SignatureException.class,
                () -> Nobleson.parser().verifyWith(Algorithms.hs256(SECRET)).parse(tampered));
    }

    /** A token signed with one HMAC secret must not verify under a different one. */
    @Test
    void differentSecretIsRejected() {
        String token = Nobleson.builder().subject("user").signWith(Algorithms.hs256(SECRET)).generate();
        byte[] otherSecret =
                "a-completely-different-but-still-long-enough-secret-key-value-123".getBytes(StandardCharsets.UTF_8);

        assertThrows(SignatureException.class,
                () -> Nobleson.parser().verifyWith(Algorithms.hs256(otherSecret)).parse(token));
    }

    /** Weak (too-short) HMAC secrets are refused outright, per RFC 7518. */
    @Test
    void weakHmacSecretIsRejected() {
        assertThrows(JwtException.class, () -> Algorithms.hs256("short"));
        assertThrows(JwtException.class, () -> Algorithms.hs512(new byte[32])); // 256-bit too small for HS512
        // A properly sized secret is accepted.
        assertTrue(Nobleson.builder().subject("u").signWith(Algorithms.hs256(SECRET)).generate().length() > 0);
    }
}
