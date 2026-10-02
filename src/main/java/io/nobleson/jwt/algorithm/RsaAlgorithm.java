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

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * RSASSA-PKCS1-v1_5 signing (RS256 / RS384 / RS512).
 *
 * <p>Signing requires an RSA {@link PrivateKey}; verification requires an RSA
 * {@link PublicKey}. An instance built for verify-only has a {@code null} private
 * key and will reject {@link #sign}.
 */
public final class RsaAlgorithm implements Algorithm {

    private final String name;
    private final String jcaAlgorithm;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    RsaAlgorithm(String name, String jcaAlgorithm, PrivateKey privateKey, PublicKey publicKey) {
        this.name = name;
        this.jcaAlgorithm = jcaAlgorithm;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public byte[] sign(byte[] signingInput) {
        if (privateKey == null) {
            throw new JwtException(name + " signing requires an RSA private key");
        }
        try {
            Signature signature = Signature.getInstance(jcaAlgorithm);
            signature.initSign(privateKey);
            signature.update(signingInput);
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new JwtException("Failed to compute " + name + " signature", e);
        }
    }

    @Override
    public boolean verify(byte[] signingInput, byte[] signatureBytes) {
        if (publicKey == null) {
            throw new JwtException(name + " verification requires an RSA public key");
        }
        try {
            Signature signature = Signature.getInstance(jcaAlgorithm);
            signature.initVerify(publicKey);
            signature.update(signingInput);
            return signature.verify(signatureBytes);
        } catch (GeneralSecurityException e) {
            // A malformed signature from an attacker is a failed verification, not an error.
            return false;
        }
    }
}
