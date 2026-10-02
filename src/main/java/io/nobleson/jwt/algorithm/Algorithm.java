package io.nobleson.jwt.algorithm;

/**
 * A JWS signing algorithm. An {@code Algorithm} instance binds an algorithm
 * (e.g. HS256) to the key material needed to sign and/or verify with it.
 *
 * <p>The {@link #name()} is the JWA identifier written into the token's
 * {@code alg} header (RFC 7518). The parser enforces that the token's header
 * {@code alg} matches the verifier's {@code name()}, which blocks algorithm
 * confusion attacks.
 */
public sealed interface Algorithm permits HmacAlgorithm, RsaAlgorithm, EcAlgorithm {

    /** The JWA {@code alg} identifier, e.g. {@code "HS256"}, {@code "RS256"}, {@code "ES256"}. */
    String name();

    /** Produce the JWS signature over {@code signingInput} (the {@code header.payload} ASCII bytes). */
    byte[] sign(byte[] signingInput);

    /** Return {@code true} iff {@code signature} is a valid JWS signature over {@code signingInput}. */
    boolean verify(byte[] signingInput, byte[] signature);
}
