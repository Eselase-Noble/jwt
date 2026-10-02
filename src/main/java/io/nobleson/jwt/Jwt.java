package io.nobleson.jwt;

/**
 * A parsed and verified JWT. Returned by {@link JwtParser#parse(String)}; by the
 * time you hold one, its signature and time-based claims have already been checked.
 */
public final class Jwt {

    private final Header header;
    private final Claims claims;
    private final String token;

    Jwt(Header header, Claims claims, String token) {
        this.header = header;
        this.claims = claims;
        this.token = token;
    }

    public Header header() {
        return header;
    }

    public Claims claims() {
        return claims;
    }

    /** The original compact serialization this {@code Jwt} was parsed from. */
    public String token() {
        return token;
    }

    // Shortcuts for the most common registered claims.

    public String subject() {
        return claims.subject();
    }

    public String issuer() {
        return claims.issuer();
    }

    public String audience() {
        return claims.audience();
    }

    @Override
    public String toString() {
        return "Jwt{header=" + header + ", claims=" + claims + '}';
    }
}
