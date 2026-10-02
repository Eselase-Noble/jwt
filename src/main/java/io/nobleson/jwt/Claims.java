/*
 * Nobleson JWT
 * https://github.com/Eselase-Noble/jwt
 *
 * Author:  Noble Eselase Vulley
 * Version: 0.1.0
 * Date:    2026-10-02
 */
package io.nobleson.jwt;

import io.nobleson.jwt.exception.JwtException;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The payload of a JWT: its claims. Registered claims (RFC 7519) have dedicated
 * accessors; everything else is reachable by name with {@link #get(String, Class)}.
 *
 * <p>Numeric date claims ({@code exp}, {@code nbf}, {@code iat}) are stored as
 * seconds since the epoch and surfaced as {@link Instant}.
 */
public final class Claims {

    public static final String ISSUER = "iss";
    public static final String SUBJECT = "sub";
    public static final String AUDIENCE = "aud";
    public static final String EXPIRATION = "exp";
    public static final String NOT_BEFORE = "nbf";
    public static final String ISSUED_AT = "iat";
    public static final String JWT_ID = "jti";

    private final Map<String, Object> values;

    Claims(Map<String, Object> values) {
        this.values = values;
    }

    // ---- registered claims ----

    public String issuer() {
        return get(ISSUER, String.class);
    }

    public String subject() {
        return get(SUBJECT, String.class);
    }

    public String audience() {
        return get(AUDIENCE, String.class);
    }

    public String id() {
        return get(JWT_ID, String.class);
    }

    public Instant expiration() {
        return instant(EXPIRATION);
    }

    public Instant notBefore() {
        return instant(NOT_BEFORE);
    }

    public Instant issuedAt() {
        return instant(ISSUED_AT);
    }

    // ---- generic access ----

    /** {@code true} if a claim with this name is present. */
    public boolean has(String name) {
        return values.containsKey(name);
    }

    /** The raw value of a claim, or {@code null} if absent. */
    public Object get(String name) {
        return values.get(name);
    }

    /**
     * The value of a claim coerced to {@code type}, or {@code null} if absent.
     * Throws {@link JwtException} if the stored value is not assignable to {@code type}.
     */
    public <T> T get(String name, Class<T> type) {
        Object value = values.get(name);
        if (value == null) {
            return null;
        }
        if (!type.isInstance(value)) {
            throw new JwtException("Claim '" + name + "' is a " + value.getClass().getSimpleName()
                    + ", not a " + type.getSimpleName());
        }
        return type.cast(value);
    }

    /** An unmodifiable view of every claim. */
    public Map<String, Object> asMap() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(values));
    }

    private Instant instant(String name) {
        Object value = values.get(name);
        if (value == null) {
            return null;
        }
        if (value instanceof Number number) {
            return Instant.ofEpochSecond(number.longValue());
        }
        throw new JwtException("Claim '" + name + "' is not a numeric date");
    }

    @Override
    public String toString() {
        return "Claims" + values;
    }
}
