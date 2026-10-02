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
import io.nobleson.jwt.internal.Json;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A set of {@link Jwk}s, matching the {@code {"keys":[...]}} JWKS document (RFC 7517)
 * that OIDC providers publish at their {@code jwks_uri}. Look a key up by its {@code kid},
 * or publish your own set with {@link #toJson()}.
 */
public final class JwkSet {

    private final List<Jwk> keys;

    public JwkSet(List<Jwk> keys) {
        this.keys = List.copyOf(keys);
    }

    /** Parse a JWKS JSON document. Keys that fail to parse are skipped, not fatal. */
    public static JwkSet parse(String json) {
        Map<String, Object> root = Json.readMap(json.getBytes(StandardCharsets.UTF_8));
        Object keysField = root.get("keys");
        if (!(keysField instanceof List<?> list)) {
            throw new JwtException("JWKS document has no 'keys' array");
        }
        List<Jwk> parsed = new ArrayList<>();
        for (Object element : list) {
            if (element instanceof Map<?, ?> map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> jwk = (Map<String, Object>) map;
                try {
                    parsed.add(Jwk.from(jwk));
                } catch (JwtException ignored) {
                    // Skip keys we cannot use (unsupported type, malformed) rather than
                    // failing the whole set; a provider may list keys for other purposes.
                }
            }
        }
        return new JwkSet(parsed);
    }

    /** The key with this id, or {@code null} if the set has none. A {@code null} id matches a single unnamed key. */
    public Jwk byKid(String kid) {
        if (kid == null && keys.size() == 1) {
            return keys.get(0);
        }
        for (Jwk key : keys) {
            if (key.kid() != null && key.kid().equals(kid)) {
                return key;
            }
        }
        return null;
    }

    public List<Jwk> keys() {
        return keys;
    }

    /** This set as a JWKS JSON document. */
    public String toJson() {
        List<Map<String, Object>> keyMaps = new ArrayList<>();
        for (Jwk key : keys) {
            keyMaps.add(key.toMap());
        }
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("keys", keyMaps);
        return new String(Json.write(root), StandardCharsets.UTF_8);
    }
}
