package io.nobleson.jwt.internal;

import io.nobleson.jwt.exception.MalformedJwtException;

import java.util.Base64;

/**
 * Base64URL encoding without padding, as required by JWS/JWT (RFC 7515, Appendix C).
 */
public final class Base64Url {

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private Base64Url() {
    }

    public static String encode(byte[] bytes) {
        return ENCODER.encodeToString(bytes);
    }

    public static byte[] decode(String value) {
        try {
            return DECODER.decode(value);
        } catch (IllegalArgumentException e) {
            throw new MalformedJwtException("Invalid Base64URL segment in token", e);
        }
    }
}
