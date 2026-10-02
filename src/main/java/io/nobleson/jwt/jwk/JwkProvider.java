/*
 * Nobleson JWT
 * https://github.com/Eselase-Noble/jwt
 *
 * Author:  Noble Eselase Vulley
 * Version: 0.2.0
 * Date:    2026-10-02
 */
package io.nobleson.jwt.jwk;

/**
 * Supplies the {@link Jwk} for a given {@code kid} when verifying a token. Implement
 * this to source keys however you like; {@link StaticJwkProvider} and
 * {@link RemoteJwkProvider} cover the common cases.
 */
public interface JwkProvider {

    /**
     * The key with this id, or {@code null} if none is known. A {@code null} {@code kid}
     * should return the sole key when the source has exactly one.
     */
    Jwk get(String kid);
}
