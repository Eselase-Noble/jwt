/*
 * Nobleson JWT
 * https://github.com/Eselase-Noble/jwt
 *
 * Author:  Noble Eselase Vulley
 * Version: 0.2.0
 * Date:    2026-10-02
 */
package io.nobleson.jwt;

import com.sun.net.httpserver.HttpServer;
import io.nobleson.jwt.algorithm.Algorithms;
import io.nobleson.jwt.exception.JwtException;
import io.nobleson.jwt.exception.SignatureException;
import io.nobleson.jwt.internal.Base64Url;
import io.nobleson.jwt.jwk.Jwk;
import io.nobleson.jwt.jwk.JwkSet;
import io.nobleson.jwt.jwk.RemoteJwkProvider;
import io.nobleson.jwt.jwk.StaticJwkProvider;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwksTest {

    @Test
    void verifyRsaTokenViaStaticJwks() {
        KeyPair rsa = Keys.rsaKeyPair();
        JwkSet set = new JwkSet(List.of(Jwk.fromRsa("key-1", (RSAPublicKey) rsa.getPublic())));

        String token = Nobleson.builder()
                .subject("user").keyId("key-1")
                .signWith(Algorithms.rs256(rsa.getPrivate()))
                .generate();

        Jwt jwt = Nobleson.parser()
                .verifyWith(new StaticJwkProvider(set))
                .parse(token);
        assertEquals("user", jwt.subject());
    }

    @Test
    void verifyEcTokenViaStaticJwks() {
        KeyPair ec = Keys.ecKeyPair();
        JwkSet set = new JwkSet(List.of(Jwk.fromEc("ec-1", (ECPublicKey) ec.getPublic())));

        String token = Nobleson.builder()
                .subject("user").keyId("ec-1")
                .signWith(Algorithms.es256(ec.getPrivate()))
                .generate();

        Jwt jwt = Nobleson.parser().verifyWith(new StaticJwkProvider(set)).parse(token);
        assertEquals("user", jwt.subject());
    }

    @Test
    void jwksJsonRoundTrips() {
        KeyPair rsa = Keys.rsaKeyPair();
        JwkSet original = new JwkSet(List.of(Jwk.fromRsa("key-1", (RSAPublicKey) rsa.getPublic())));

        String json = original.toJson();
        assertTrue(json.contains("\"kty\":\"RSA\""));

        String token = Nobleson.builder().subject("user").keyId("key-1")
                .signWith(Algorithms.rs256(rsa.getPrivate())).generate();

        // Parse the JSON back and use it to verify.
        Jwt jwt = Nobleson.parser()
                .verifyWith(StaticJwkProvider.of(json))
                .parse(token);
        assertEquals("user", jwt.subject());
    }

    @Test
    void unknownKidIsRejected() {
        KeyPair rsa = Keys.rsaKeyPair();
        JwkSet set = new JwkSet(List.of(Jwk.fromRsa("key-1", (RSAPublicKey) rsa.getPublic())));
        String token = Nobleson.builder().subject("user").keyId("other-key")
                .signWith(Algorithms.rs256(rsa.getPrivate())).generate();

        assertThrows(SignatureException.class,
                () -> Nobleson.parser().verifyWith(new StaticJwkProvider(set)).parse(token));
    }

    @Test
    void hmacTokenAgainstJwksIsRejected() {
        KeyPair rsa = Keys.rsaKeyPair();
        JwkSet set = new JwkSet(List.of(Jwk.fromRsa("key-1", (RSAPublicKey) rsa.getPublic())));

        // Attacker forges an HS256 token but tags it with a real kid from the JWKS.
        String forged = Nobleson.builder()
                .subject("attacker").keyId("key-1")
                .signWith(Algorithms.hs256("a-secret-that-is-at-least-32-bytes-long!!"))
                .generate();

        // The RSA JWK cannot produce an HMAC algorithm, so it is rejected.
        assertThrows(JwtException.class,
                () -> Nobleson.parser().verifyWith(new StaticJwkProvider(set)).parse(forged));
    }

    @Test
    void algNoneAgainstJwksIsRejected() {
        KeyPair rsa = Keys.rsaKeyPair();
        JwkSet set = new JwkSet(List.of(Jwk.fromRsa("key-1", (RSAPublicKey) rsa.getPublic())));

        String header = Base64Url.encode("{\"alg\":\"none\",\"kid\":\"key-1\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64Url.encode("{\"sub\":\"admin\"}".getBytes(StandardCharsets.UTF_8));
        String noneToken = header + "." + payload + ".";

        assertThrows(JwtException.class,
                () -> Nobleson.parser().verifyWith(new StaticJwkProvider(set)).parse(noneToken));
    }

    @Test
    void permittedAlgorithmsPinsTheAcceptableSet() {
        KeyPair rsa = Keys.rsaKeyPair();
        JwkSet set = new JwkSet(List.of(Jwk.fromRsa("key-1", (RSAPublicKey) rsa.getPublic())));
        String token = Nobleson.builder().subject("user").keyId("key-1")
                .signWith(Algorithms.rs256(rsa.getPrivate())).generate();

        // RS256 permitted: fine.
        assertEquals("user", Nobleson.parser().verifyWith(new StaticJwkProvider(set))
                .permittedAlgorithms("RS256").parse(token).subject());

        // Only ES256 permitted: the RS256 token is refused.
        assertThrows(SignatureException.class, () -> Nobleson.parser()
                .verifyWith(new StaticJwkProvider(set))
                .permittedAlgorithms("ES256")
                .parse(token));
    }

    @Test
    void remoteProviderFetchesAndHandlesRotation() throws Exception {
        KeyPair key1 = Keys.rsaKeyPair();
        KeyPair key2 = Keys.rsaKeyPair();

        // The server serves a JWKS we can swap at will, to simulate key rotation.
        AtomicReference<String> served = new AtomicReference<>(
                new JwkSet(List.of(Jwk.fromRsa("k1", (RSAPublicKey) key1.getPublic()))).toJson());

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/jwks", exchange -> {
            byte[] body = served.get().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            URI uri = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/jwks");
            // Large TTL, zero throttle: the only refetch we exercise is the unknown-kid path.
            RemoteJwkProvider provider = new RemoteJwkProvider(uri, Duration.ofHours(1), Duration.ZERO);

            String token1 = Nobleson.builder().subject("u1").keyId("k1")
                    .signWith(Algorithms.rs256(key1.getPrivate())).generate();
            assertEquals("u1", Nobleson.parser().verifyWith(provider).parse(token1).subject());

            // Rotate: the provider now signs with k2, and the server starts publishing it.
            served.set(new JwkSet(List.of(
                    Jwk.fromRsa("k1", (RSAPublicKey) key1.getPublic()),
                    Jwk.fromRsa("k2", (RSAPublicKey) key2.getPublic()))).toJson());

            String token2 = Nobleson.builder().subject("u2").keyId("k2")
                    .signWith(Algorithms.rs256(key2.getPrivate())).generate();

            // The cache does not know k2 yet; the provider refetches and finds it.
            assertEquals("u2", Nobleson.parser().verifyWith(provider).parse(token2).subject());
        } finally {
            server.stop(0);
        }
    }
}
