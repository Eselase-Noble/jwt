package io.nobleson.jwt.exception;

/**
 * The signature could not be verified: it does not match the token's contents,
 * or the token's {@code alg} header does not match the algorithm the parser was
 * told to verify with (an "algorithm confusion" attempt).
 */
public class SignatureException extends JwtException {

    public SignatureException(String message) {
        super(message);
    }

    public SignatureException(String message, Throwable cause) {
        super(message, cause);
    }
}
