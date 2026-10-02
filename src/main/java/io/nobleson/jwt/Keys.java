package io.nobleson.jwt;

import io.nobleson.jwt.exception.JwtException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

/**
 * One-call generators for strong signing keys. Use these when you need a fresh
 * secret or key pair and don't already have one.
 *
 * <pre>{@code
 * SecretKey secret = Keys.hmacSecret();          // 256-bit, for HS256
 * KeyPair   rsa    = Keys.rsaKeyPair();           // 2048-bit, for RS*
 * KeyPair   ec     = Keys.ecKeyPair();            // P-256, for ES256
 * }</pre>
 */
public final class Keys {

    private Keys() {
    }

    /** A random 256-bit secret suitable for HS256. */
    public static SecretKey hmacSecret() {
        return hmacSecret(256);
    }

    /** A random HMAC secret of the given key size in bits (256, 384 or 512). */
    public static SecretKey hmacSecret(int bits) {
        String algorithm = switch (bits) {
            case 256 -> "HmacSHA256";
            case 384 -> "HmacSHA384";
            case 512 -> "HmacSHA512";
            default -> throw new JwtException("HMAC key size must be 256, 384 or 512 bits");
        };
        try {
            KeyGenerator generator = KeyGenerator.getInstance(algorithm);
            generator.init(bits);
            return generator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new JwtException("Unable to generate HMAC secret", e);
        }
    }

    /** A random 2048-bit RSA key pair, for RS256/384/512. */
    public static KeyPair rsaKeyPair() {
        return rsaKeyPair(2048);
    }

    /** A random RSA key pair of the given modulus size (>= 2048 recommended). */
    public static KeyPair rsaKeyPair(int bits) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(bits);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new JwtException("Unable to generate RSA key pair", e);
        }
    }

    /** A random P-256 EC key pair, for ES256. */
    public static KeyPair ecKeyPair() {
        return ecKeyPair("secp256r1");
    }

    /**
     * A random EC key pair on the given named curve.
     * Use {@code secp256r1} for ES256, {@code secp384r1} for ES384, {@code secp521r1} for ES512.
     */
    public static KeyPair ecKeyPair(String curve) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curve));
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new JwtException("Unable to generate EC key pair for curve " + curve, e);
        }
    }
}
