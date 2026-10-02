package io.nobleson.jwt.exception;

/** The token's {@code nbf} (not-before) claim is in the future (beyond the allowed clock skew). */
public class PrematureJwtException extends JwtException {

    public PrematureJwtException(String message) {
        super(message);
    }
}
