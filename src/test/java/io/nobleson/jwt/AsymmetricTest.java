package io.nobleson.jwt;

import io.nobleson.jwt.algorithm.Algorithms;
import io.nobleson.jwt.exception.SignatureException;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AsymmetricTest {

    @Test
    void rsaRoundTripAllVariants() {
        KeyPair rsa = Keys.rsaKeyPair();
        assertRoundTrip(Algorithms.rs256(rsa.getPrivate()), Algorithms.rs256(rsa.getPublic()));
        assertRoundTrip(Algorithms.rs384(rsa.getPrivate()), Algorithms.rs384(rsa.getPublic()));
        assertRoundTrip(Algorithms.rs512(rsa.getPrivate()), Algorithms.rs512(rsa.getPublic()));
    }

    @Test
    void ecRoundTripAllCurves() {
        KeyPair p256 = Keys.ecKeyPair("secp256r1");
        assertRoundTrip(Algorithms.es256(p256.getPrivate()), Algorithms.es256(p256.getPublic()));

        KeyPair p384 = Keys.ecKeyPair("secp384r1");
        assertRoundTrip(Algorithms.es384(p384.getPrivate()), Algorithms.es384(p384.getPublic()));

        KeyPair p521 = Keys.ecKeyPair("secp521r1");
        assertRoundTrip(Algorithms.es512(p521.getPrivate()), Algorithms.es512(p521.getPublic()));
    }

    @Test
    void ecSignVerifyRepeatedlyToExerciseDerConversion() {
        // ECDSA is randomized; run many iterations so short/padded r,s values occur.
        KeyPair p256 = Keys.ecKeyPair("secp256r1");
        for (int i = 0; i < 200; i++) {
            String token = Nobleson.builder()
                    .subject("iteration-" + i)
                    .signWith(Algorithms.es256(p256.getPrivate()))
                    .generate();
            Jwt jwt = Nobleson.parser().verifyWith(Algorithms.es256(p256.getPublic())).parse(token);
            assertEquals("iteration-" + i, jwt.subject());
        }
    }

    @Test
    void rsaTokenRejectedByDifferentKey() {
        String token = Nobleson.builder()
                .subject("user")
                .signWith(Algorithms.rs256(Keys.rsaKeyPair().getPrivate()))
                .generate();
        assertThrows(SignatureException.class, () ->
                Nobleson.parser().verifyWith(Algorithms.rs256(Keys.rsaKeyPair().getPublic())).parse(token));
    }

    private void assertRoundTrip(io.nobleson.jwt.algorithm.Algorithm signer,
                                 io.nobleson.jwt.algorithm.Algorithm verifier) {
        String token = Nobleson.builder().subject("user").claim("n", 42).signWith(signer).generate();
        Jwt jwt = Nobleson.parser().verifyWith(verifier).parse(token);
        assertEquals("user", jwt.subject());
        assertEquals(42, jwt.claims().get("n", Integer.class));
    }
}
