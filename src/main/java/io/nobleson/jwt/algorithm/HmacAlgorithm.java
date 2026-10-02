package io.nobleson.jwt.algorithm;

import io.nobleson.jwt.exception.JwtException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/**
 * HMAC-SHA signing (HS256 / HS384 / HS512) using a shared secret.
 */
public final class HmacAlgorithm implements Algorithm {

    private final String name;
    private final String macAlgorithm;
    private final SecretKey key;

    HmacAlgorithm(String name, String macAlgorithm, SecretKey key) {
        this.name = name;
        this.macAlgorithm = macAlgorithm;
        this.key = key;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public byte[] sign(byte[] signingInput) {
        try {
            Mac mac = Mac.getInstance(macAlgorithm);
            mac.init(key);
            return mac.doFinal(signingInput);
        } catch (GeneralSecurityException e) {
            throw new JwtException("Failed to compute " + name + " signature", e);
        }
    }

    @Override
    public boolean verify(byte[] signingInput, byte[] signature) {
        // Recompute and compare in constant time.
        byte[] expected = sign(signingInput);
        return MessageDigest.isEqual(expected, signature);
    }
}
