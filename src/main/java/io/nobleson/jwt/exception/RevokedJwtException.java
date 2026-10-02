/*
 * Nobleson JWT
 * https://github.com/Eselase-Noble/jwt
 *
 * Author:  Noble Eselase Vulley
 * Version: 0.1.0
 * Date:    2026-10-02
 */
package io.nobleson.jwt.exception;

/**
 * The token verified correctly but has been revoked (for example, the user logged
 * out and its {@code jti} was placed on a {@link io.nobleson.jwt.revocation.TokenDenylist}).
 */
public class RevokedJwtException extends JwtException {

    public RevokedJwtException(String message) {
        super(message);
    }
}
