package io.nobleson.jwt.internal;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.nobleson.jwt.exception.MalformedJwtException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Thin wrapper around a single, shared Jackson {@link ObjectMapper}. Keeping all
 * Jackson usage behind this class means the JSON backend can be swapped without
 * touching the rest of the library.
 */
public final class Json {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final TypeReference<LinkedHashMap<String, Object>> MAP_TYPE =
            new TypeReference<>() {
            };

    private Json() {
    }

    /** Serialize a map to its compact JSON UTF-8 bytes. */
    public static byte[] write(Map<String, Object> map) {
        try {
            return MAPPER.writeValueAsBytes(map);
        } catch (Exception e) {
            // Maps built by this library are always serializable; treat as a bug.
            throw new IllegalStateException("Failed to serialize JWT segment to JSON", e);
        }
    }

    /** Parse JSON bytes into an ordered string-keyed map. */
    public static LinkedHashMap<String, Object> readMap(byte[] json) {
        try {
            return MAPPER.readValue(json, MAP_TYPE);
        } catch (Exception e) {
            throw new MalformedJwtException("Token segment is not valid JSON object", e);
        }
    }
}
