/*
 * Nobleson JWT
 * https://github.com/Eselase-Noble/jwt
 *
 * Author:  Noble Eselase Vulley
 * Version: 0.1.0
 * Date:    2026-10-02
 */
package io.nobleson.jwt;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The JOSE header of a JWT (RFC 7515): the {@code alg} and {@code typ}, plus any
 * extra fields such as {@code kid}.
 */
public final class Header {

    public static final String ALGORITHM = "alg";
    public static final String TYPE = "typ";
    public static final String KEY_ID = "kid";

    private final Map<String, Object> values;

    Header(Map<String, Object> values) {
        this.values = values;
    }

    /** The signing algorithm identifier, e.g. {@code "HS256"}. */
    public String algorithm() {
        return get(ALGORITHM, String.class);
    }

    /** The token type, usually {@code "JWT"}. */
    public String type() {
        return get(TYPE, String.class);
    }

    /** The key id hint, or {@code null} if none was set. */
    public String keyId() {
        return get(KEY_ID, String.class);
    }

    public Object get(String name) {
        return values.get(name);
    }

    public <T> T get(String name, Class<T> type) {
        Object value = values.get(name);
        return value == null ? null : type.cast(value);
    }

    public Map<String, Object> asMap() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(values));
    }

    @Override
    public String toString() {
        return "Header" + values;
    }
}
