package io.nobleson.jwt.spring;

/**
 * Where {@link JwtService} looks for the token on an incoming request.
 *
 * <ul>
 *   <li>{@link #BEARER} reads the {@code Authorization: Bearer <token>} header. This is the default.</li>
 *   <li>{@link #COOKIE} reads a named cookie, which suits browser apps that keep the
 *       token in an {@code HttpOnly} cookie instead of JavaScript-reachable storage.</li>
 * </ul>
 */
public enum TokenSource {
    BEARER,
    COOKIE
}
