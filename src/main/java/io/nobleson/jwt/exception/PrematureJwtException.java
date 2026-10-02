/*
 * Nobleson JWT
 * https://github.com/Eselase-Noble/jwt
 *
 * Author:  Noble Eselase Vulley
 * Version: 0.1.0
 * Date:    2026-10-02
 */
package io.nobleson.jwt.exception;

/** The token's {@code nbf} (not-before) claim is in the future (beyond the allowed clock skew). */
public class PrematureJwtException extends JwtException {

    public PrematureJwtException(String message) {
        super(message);
    }
}
