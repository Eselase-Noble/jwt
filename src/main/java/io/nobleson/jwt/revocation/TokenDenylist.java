/*
 * Nobleson JWT
 * https://github.com/Eselase-Noble/jwt
 *
 * Author:  Noble Eselase Vulley
 * Version: 0.1.0
 * Date:    2026-10-02
 */
package io.nobleson.jwt.revocation;

import java.time.Instant;

/**
 * A record of tokens that have been revoked before their natural expiry, keyed by
 * their {@code jti} (token id). This is the small piece of server-side state that
 * makes "log out now" possible, since a signed JWT is otherwise valid until it expires.
 *
 * <p>Implementations should forget an entry once its expiry has passed, because an
 * expired token is already rejected on its own and no longer needs to be listed.
 *
 * <p>The interface is framework-free. Use {@link InMemoryTokenDenylist} for a single
 * instance, or back it with Redis or a database for a distributed deployment.
 */
public interface TokenDenylist {

    /** Revoke the token with this id. {@code expiry} is when it would have expired anyway. */
    void revoke(String tokenId, Instant expiry);

    /** {@code true} if the token with this id has been revoked and has not yet expired. */
    boolean isRevoked(String tokenId);
}
