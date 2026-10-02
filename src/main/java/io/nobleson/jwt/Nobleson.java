package io.nobleson.jwt;

/**
 * The entry point to Nobleson. Everything starts here:
 *
 * <pre>{@code
 * // create
 * String token = Nobleson.builder()
 *         .subject("user-123")
 *         .expiresIn(Duration.ofHours(1))
 *         .signWith(Algorithms.hs256(secret))
 *         .generate();
 *
 * // verify
 * Jwt jwt = Nobleson.parser()
 *         .verifyWith(Algorithms.hs256(secret))
 *         .parse(token);
 * }</pre>
 */
public final class Nobleson {

    private Nobleson() {
    }

    /** Start building a new token. */
    public static JwtBuilder builder() {
        return new JwtBuilder();
    }

    /** Start configuring a verifier/parser. */
    public static JwtParser parser() {
        return new JwtParser();
    }
}
