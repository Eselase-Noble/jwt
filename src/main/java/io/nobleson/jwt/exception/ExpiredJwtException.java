package io.nobleson.jwt.exception;

/** The token's {@code exp} (expiration) claim is in the past (beyond the allowed clock skew). */
public class ExpiredJwtException extends JwtException {

    public ExpiredJwtException(String message) {
        super(message);
    }
}
