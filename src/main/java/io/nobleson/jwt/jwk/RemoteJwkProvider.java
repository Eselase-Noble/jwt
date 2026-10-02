/*
 * Nobleson JWT
 * https://github.com/Eselase-Noble/jwt
 *
 * Author:  Noble Eselase Vulley
 * Version: 0.2.0
 * Date:    2026-10-02
 */
package io.nobleson.jwt.jwk;

import io.nobleson.jwt.exception.JwtException;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;

/**
 * A {@link JwkProvider} that fetches a JWKS document over HTTPS (for example an OIDC
 * provider's {@code jwks_uri}) and caches it. It handles key rotation: when a token
 * references a {@code kid} the cache does not know, it refetches once (throttled) so a
 * newly rotated-in key is picked up without a restart. Expired cache entries are
 * refreshed on the next lookup.
 *
 * <p>Thread-safe: the cache is a volatile reference and refreshes are serialized.
 * The HTTP fetch is a {@code protected} method so it can be overridden in tests or to
 * add custom headers.
 */
public class RemoteJwkProvider implements JwkProvider {

    private final URI uri;
    private final HttpClient http;
    private final Duration cacheTtl;
    private final Duration minRefreshInterval;

    private volatile JwkSet cache;
    private volatile Instant lastFetch = Instant.EPOCH;

    /** Cache for one hour, and refresh on an unknown kid at most once every 30 seconds. */
    public RemoteJwkProvider(URI uri) {
        this(uri, Duration.ofHours(1), Duration.ofSeconds(30));
    }

    public RemoteJwkProvider(URI uri, Duration cacheTtl, Duration minRefreshInterval) {
        this(uri, cacheTtl, minRefreshInterval, HttpClient.newHttpClient());
    }

    public RemoteJwkProvider(URI uri, Duration cacheTtl, Duration minRefreshInterval, HttpClient http) {
        this.uri = uri;
        this.cacheTtl = cacheTtl;
        this.minRefreshInterval = minRefreshInterval;
        this.http = http;
    }

    @Override
    public Jwk get(String kid) {
        JwkSet set = cache;
        if (set == null || isStale()) {
            set = refresh();
        }

        Jwk key = set.byKid(kid);
        if (key == null && canRefreshNow()) {
            // The kid is unknown: the provider may have rotated its keys. Refetch once.
            set = refresh();
            key = set.byKid(kid);
        }
        return key;
    }

    /** Force a fresh fetch now, replacing the cache. */
    public synchronized JwkSet refresh() {
        JwkSet fetched = JwkSet.parse(fetch());
        cache = fetched;
        lastFetch = Instant.now();
        return fetched;
    }

    /** Perform the HTTP GET and return the response body. Override to customize. */
    protected String fetch() {
        try {
            HttpRequest request = HttpRequest.newBuilder(uri)
                    .GET()
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(10))
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new JwtException("JWKS fetch from " + uri + " returned HTTP " + response.statusCode());
            }
            return response.body();
        } catch (JwtException e) {
            throw e;
        } catch (Exception e) {
            throw new JwtException("Could not fetch JWKS from " + uri, e);
        }
    }

    private boolean isStale() {
        return Instant.now().isAfter(lastFetch.plus(cacheTtl));
    }

    private boolean canRefreshNow() {
        return Instant.now().isAfter(lastFetch.plus(minRefreshInterval));
    }
}
