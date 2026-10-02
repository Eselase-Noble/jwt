/*
 * Nobleson JWT
 * https://github.com/Eselase-Noble/jwt
 *
 * Author:  Noble Eselase Vulley
 * Version: 0.1.0
 * Date:    2026-10-02
 */
package io.nobleson.jwt.exception;

/** The token's {@code exp} (expiration) claim is in the past (beyond the allowed clock skew). */
public class ExpiredJwtException extends JwtException {

    public ExpiredJwtException(String message) {
        super(message);
    }
}
