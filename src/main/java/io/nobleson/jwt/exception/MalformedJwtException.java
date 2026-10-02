package io.nobleson.jwt.exception;

/**
 * The token is not a well-formed JWT: it does not have three dot-separated parts,
 * a part is not valid Base64URL, or a part is not valid JSON.
 */
public class MalformedJwtException extends JwtException {

    public MalformedJwtException(String message) {
        super(message);
    }

    public MalformedJwtException(String message, Throwable cause) {
        super(message, cause);
    }
}
