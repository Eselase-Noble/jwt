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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * A simple thread-safe {@link TokenDenylist} held in memory. Entries are dropped
 * automatically once they pass the expiry they were revoked with, so the map stays
 * bounded by the number of still-live revoked tokens.
 *
 * <p>Good for a single application instance. For several instances behind a load
 * balancer, use a shared store (Redis, a database) so a logout on one node is seen
 * by all of them.
 */
public class InMemoryTokenDenylist implements TokenDenylist {

    protected final ConcurrentMap<String, Instant> revoked = new ConcurrentHashMap<>();

    @Override
    public void revoke(String tokenId, Instant expiry) {
        if (tokenId == null) {
            return;
        }
        // No expiry means we cannot know when it is safe to forget; keep it forever.
        revoked.put(tokenId, expiry == null ? Instant.MAX : expiry);
        // Revocation (logout) is infrequent, so this is the cheap place to sweep
        // expired entries. It keeps the map bounded without scanning on the hot path.
        purgeExpired();
    }

    @Override
    public boolean isRevoked(String tokenId) {
        if (tokenId == null) {
            return false;
        }
        // O(1): look up just this id and drop it lazily if it has expired, rather
        // than scanning the whole map on every request.
        Instant expiry = revoked.get(tokenId);
        if (expiry == null) {
            return false;
        }
        if (expiry.isBefore(Instant.now())) {
            revoked.remove(tokenId, expiry);
            return false;
        }
        return true;
    }

    /** The number of still-live revoked tokens being tracked. */
    public int size() {
        purgeExpired();
        return revoked.size();
    }

    protected void purgeExpired() {
        Instant now = Instant.now();
        revoked.values().removeIf(expiry -> expiry.isBefore(now));
    }
}
