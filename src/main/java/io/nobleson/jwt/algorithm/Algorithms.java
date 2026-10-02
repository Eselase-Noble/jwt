/*
 * Nobleson JWT
 * https://github.com/Eselase-Noble/jwt
 *
 * Author:  Noble Eselase Vulley
 * Version: 0.1.0
 * Date:    2026-10-02
 */
package io.nobleson.jwt.algorithm;

import io.nobleson.jwt.exception.JwtException;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Factory methods for every supported {@link Algorithm}. This is the single place
 * you choose how a token is signed or verified.
 *
 * <pre>{@code
 * Algorithm hmac = Algorithms.hs256("my-very-secret-key");
 * Algorithm rsa  = Algorithms.rs256(keyPair);     // sign + verify
 * Algorithm ec   = Algorithms.es256(publicKey);   // verify only
 * }</pre>
 */
public final class Algorithms {

    private Algorithms() {
    }

    // ---------- HMAC ----------

    public static Algorithm hs256(byte[] secret) {
        return hmac("HS256", "HmacSHA256", 32, secret);
    }

    public static Algorithm hs384(byte[] secret) {
        return hmac("HS384", "HmacSHA384", 48, secret);
    }

    public static Algorithm hs512(byte[] secret) {
        return hmac("HS512", "HmacSHA512", 64, secret);
    }

    /** Convenience: use a UTF-8 string as the HMAC secret. */
    public static Algorithm hs256(String secret) {
        return hs256(secret.getBytes(StandardCharsets.UTF_8));
    }

    public static Algorithm hs384(String secret) {
        return hs384(secret.getBytes(StandardCharsets.UTF_8));
    }

    public static Algorithm hs512(String secret) {
        return hs512(secret.getBytes(StandardCharsets.UTF_8));
    }

    private static Algorithm hmac(String name, String macAlgorithm, int minBytes, byte[] secret) {
        if (secret == null || secret.length == 0) {
            throw new JwtException(name + " requires a non-empty secret");
        }
        // RFC 7518 §3.2: an HMAC key must be at least as long as the hash output.
        // A shorter secret is a real weakness, so reject it rather than sign with it.
        if (secret.length < minBytes) {
            throw new JwtException(name + " requires a secret of at least " + minBytes
                    + " bytes (" + (minBytes * 8) + " bits); got " + secret.length
                    + ". Generate one with Keys.hmacSecret(" + (minBytes * 8) + ").");
        }
        return new HmacAlgorithm(name, macAlgorithm, new SecretKeySpec(secret, macAlgorithm));
    }

    // ---------- RSA ----------

    public static Algorithm rs256(KeyPair keyPair) {
        return rsa("RS256", "SHA256withRSA", keyPair.getPrivate(), keyPair.getPublic());
    }

    public static Algorithm rs384(KeyPair keyPair) {
        return rsa("RS384", "SHA384withRSA", keyPair.getPrivate(), keyPair.getPublic());
    }

    public static Algorithm rs512(KeyPair keyPair) {
        return rsa("RS512", "SHA512withRSA", keyPair.getPrivate(), keyPair.getPublic());
    }

    /** Sign-only (private key). */
    public static Algorithm rs256(PrivateKey privateKey) {
        return rsa("RS256", "SHA256withRSA", privateKey, null);
    }

    public static Algorithm rs384(PrivateKey privateKey) {
        return rsa("RS384", "SHA384withRSA", privateKey, null);
    }

    public static Algorithm rs512(PrivateKey privateKey) {
        return rsa("RS512", "SHA512withRSA", privateKey, null);
    }

    /** Verify-only (public key). */
    public static Algorithm rs256(PublicKey publicKey) {
        return rsa("RS256", "SHA256withRSA", null, publicKey);
    }

    public static Algorithm rs384(PublicKey publicKey) {
        return rsa("RS384", "SHA384withRSA", null, publicKey);
    }

    public static Algorithm rs512(PublicKey publicKey) {
        return rsa("RS512", "SHA512withRSA", null, publicKey);
    }

    private static Algorithm rsa(String name, String jca, PrivateKey priv, PublicKey pub) {
        return new RsaAlgorithm(name, jca, priv, pub);
    }

    // ---------- EC ----------

    public static Algorithm es256(KeyPair keyPair) {
        return ec("ES256", "SHA256withECDSA", 32, keyPair.getPrivate(), keyPair.getPublic());
    }

    public static Algorithm es384(KeyPair keyPair) {
        return ec("ES384", "SHA384withECDSA", 48, keyPair.getPrivate(), keyPair.getPublic());
    }

    public static Algorithm es512(KeyPair keyPair) {
        return ec("ES512", "SHA512withECDSA", 66, keyPair.getPrivate(), keyPair.getPublic());
    }

    /** Sign-only (private key). */
    public static Algorithm es256(PrivateKey privateKey) {
        return ec("ES256", "SHA256withECDSA", 32, privateKey, null);
    }

    public static Algorithm es384(PrivateKey privateKey) {
        return ec("ES384", "SHA384withECDSA", 48, privateKey, null);
    }

    public static Algorithm es512(PrivateKey privateKey) {
        return ec("ES512", "SHA512withECDSA", 66, privateKey, null);
    }

    /** Verify-only (public key). */
    public static Algorithm es256(PublicKey publicKey) {
        return ec("ES256", "SHA256withECDSA", 32, null, publicKey);
    }

    public static Algorithm es384(PublicKey publicKey) {
        return ec("ES384", "SHA384withECDSA", 48, null, publicKey);
    }

    public static Algorithm es512(PublicKey publicKey) {
        return ec("ES512", "SHA512withECDSA", 66, null, publicKey);
    }

    private static Algorithm ec(String name, String jca, int len, PrivateKey priv, PublicKey pub) {
        return new EcAlgorithm(name, jca, len, priv, pub);
    }
}
