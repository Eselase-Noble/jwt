package io.nobleson.jwt.algorithm;

import io.nobleson.jwt.exception.JwtException;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

/**
 * ECDSA signing (ES256 / ES384 / ES512).
 *
 * <p>The JDK's {@code SHA*withECDSA} produces an ASN.1 DER-encoded signature
 * ({@code SEQUENCE { INTEGER r, INTEGER s }}), but JWS requires the fixed-length
 * {@code R || S} concatenation (RFC 7518 §3.4). This class converts between the
 * two forms: DER &rarr; JOSE after signing, JOSE &rarr; DER before verifying.
 */
public final class EcAlgorithm implements Algorithm {

    private final String name;
    private final String jcaAlgorithm;
    /** Byte length of each of R and S for this curve (32 for P-256, 48 for P-384, 66 for P-521). */
    private final int componentLength;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    EcAlgorithm(String name, String jcaAlgorithm, int componentLength,
                PrivateKey privateKey, PublicKey publicKey) {
        this.name = name;
        this.jcaAlgorithm = jcaAlgorithm;
        this.componentLength = componentLength;
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
            throw new JwtException(name + " signing requires an EC private key");
        }
        try {
            Signature signature = Signature.getInstance(jcaAlgorithm);
            signature.initSign(privateKey);
            signature.update(signingInput);
            return derToJose(signature.sign());
        } catch (GeneralSecurityException e) {
            throw new JwtException("Failed to compute " + name + " signature", e);
        }
    }

    @Override
    public boolean verify(byte[] signingInput, byte[] joseSignature) {
        if (publicKey == null) {
            throw new JwtException(name + " verification requires an EC public key");
        }
        if (joseSignature.length != componentLength * 2) {
            return false; // Not a valid JOSE ECDSA signature for this curve.
        }
        try {
            Signature signature = Signature.getInstance(jcaAlgorithm);
            signature.initVerify(publicKey);
            signature.update(signingInput);
            return signature.verify(joseToDer(joseSignature));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    // ---- RFC 7518 §3.4 signature-format conversion ----

    /** Convert a DER-encoded {@code SEQUENCE { INTEGER r, INTEGER s }} to {@code R || S}. */
    private byte[] derToJose(byte[] der) {
        // Parse: 0x30 totalLen 0x02 rLen <r> 0x02 sLen <s>
        int offset = 0;
        if (der[offset++] != 0x30) {
            throw new JwtException("Invalid DER ECDSA signature: missing SEQUENCE tag");
        }
        // Skip the SEQUENCE length (short or long form).
        if ((der[offset] & 0x80) != 0) {
            offset += 1 + (der[offset] & 0x7F);
        } else {
            offset += 1;
        }

        if (der[offset++] != 0x02) {
            throw new JwtException("Invalid DER ECDSA signature: missing R INTEGER tag");
        }
        int rLen = der[offset++];
        byte[] r = Arrays.copyOfRange(der, offset, offset + rLen);
        offset += rLen;

        if (der[offset++] != 0x02) {
            throw new JwtException("Invalid DER ECDSA signature: missing S INTEGER tag");
        }
        int sLen = der[offset++];
        byte[] s = Arrays.copyOfRange(der, offset, offset + sLen);

        byte[] jose = new byte[componentLength * 2];
        copyUnsignedInto(r, jose, 0);
        copyUnsignedInto(s, jose, componentLength);
        return jose;
    }

    /** Convert {@code R || S} to a DER-encoded {@code SEQUENCE { INTEGER r, INTEGER s }}. */
    private byte[] joseToDer(byte[] jose) {
        byte[] r = toDerInteger(Arrays.copyOfRange(jose, 0, componentLength));
        byte[] s = toDerInteger(Arrays.copyOfRange(jose, componentLength, componentLength * 2));

        int contentLen = 2 + r.length + 2 + s.length;
        byte[] der;
        int offset;
        if (contentLen < 0x80) {
            der = new byte[2 + contentLen];
            der[0] = 0x30;
            der[1] = (byte) contentLen;
            offset = 2;
        } else {
            // Long-form length (one byte is enough for all supported curves).
            der = new byte[3 + contentLen];
            der[0] = 0x30;
            der[1] = (byte) 0x81;
            der[2] = (byte) contentLen;
            offset = 3;
        }

        der[offset++] = 0x02;
        der[offset++] = (byte) r.length;
        System.arraycopy(r, 0, der, offset, r.length);
        offset += r.length;

        der[offset++] = 0x02;
        der[offset++] = (byte) s.length;
        System.arraycopy(s, 0, der, offset, s.length);
        return der;
    }

    /** Right-align a (possibly zero-padded, possibly sign-prefixed) big-endian magnitude into {@code dest}. */
    private void copyUnsignedInto(byte[] src, byte[] dest, int destOffset) {
        // Drop any leading sign byte, then right-align within componentLength.
        int srcStart = 0;
        while (srcStart < src.length - 1 && src[srcStart] == 0) {
            srcStart++;
        }
        int len = src.length - srcStart;
        if (len > componentLength) {
            throw new JwtException("Invalid ECDSA signature component length");
        }
        System.arraycopy(src, srcStart, dest, destOffset + componentLength - len, len);
    }

    /** Turn a fixed-length big-endian magnitude into a minimal DER INTEGER body (no leading zeros, sign byte if needed). */
    private byte[] toDerInteger(byte[] magnitude) {
        int start = 0;
        while (start < magnitude.length - 1 && magnitude[start] == 0) {
            start++;
        }
        byte[] trimmed = Arrays.copyOfRange(magnitude, start, magnitude.length);
        // If the high bit is set, prepend a 0x00 so the INTEGER stays positive.
        if ((trimmed[0] & 0x80) != 0) {
            byte[] padded = new byte[trimmed.length + 1];
            System.arraycopy(trimmed, 0, padded, 1, trimmed.length);
            return padded;
        }
        return trimmed;
    }
}
