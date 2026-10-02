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
 * A {@link JwkProvider} backed by a fixed {@link JwkSet}. Use it when you already
 * hold the keys in memory, for example keys loaded from config at startup.
 */
public final class StaticJwkProvider implements JwkProvider {

    private final JwkSet keys;

    public StaticJwkProvider(JwkSet keys) {
        this.keys = keys;
    }

    /** Convenience: build from a JWKS JSON document. */
    public static StaticJwkProvider of(String jwksJson) {
        return new StaticJwkProvider(JwkSet.parse(jwksJson));
    }

    @Override
    public Jwk get(String kid) {
        return keys.byKid(kid);
    }
}
