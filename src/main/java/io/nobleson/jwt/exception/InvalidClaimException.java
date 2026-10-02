package io.nobleson.jwt.exception;

/**
 * A required claim was missing or did not have the expected value — e.g. a
 * {@code requireIssuer}/{@code requireAudience}/{@code require(name, value)}
 * expectation the token failed to satisfy.
 */
public class InvalidClaimException extends JwtException {

    public InvalidClaimException(String message) {
        super(message);
    }
}
