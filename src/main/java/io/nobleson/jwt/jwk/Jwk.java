/*
 * Nobleson JWT
 * https://github.com/Eselase-Noble/jwt
 *
 * Author:  Noble Eselase Vulley
 * Version: 0.2.0
 * Date:    2026-10-02
 */
package io.nobleson.jwt.jwk;

import io.nobleson.jwt.algorithm.Algorithm;
import io.nobleson.jwt.algorithm.Algorithms;
import io.nobleson.jwt.exception.JwtException;
import io.nobleson.jwt.internal.Base64Url;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A single JSON Web Key (RFC 7517): a public key plus its metadata ({@code kid},
 * {@code kty}, optional {@code alg}). Nobleson uses JWKs to verify tokens whose
 * signer is identified by a {@code kid} header, which is how OIDC providers and
 * rotating-key setups publish their keys.
 *
 * <p>Only public keys are modelled, and only the {@code RSA} and {@code EC} key
 * types, which is all that is needed to verify RS* and ES* tokens.
 */
public final class Jwk {

    private final String kid;
    private final String keyType;
    private final String declaredAlgorithm;
    private final PublicKey publicKey;

    private Jwk(String kid, String keyType, String declaredAlgorithm, PublicKey publicKey) {
        this.kid = kid;
        this.keyType = keyType;
        this.declaredAlgorithm = declaredAlgorithm;
        this.publicKey = publicKey;
    }

    public String kid() {
        return kid;
    }

    public String keyType() {
        return keyType;
    }

    /** The {@code alg} the key owner declared, or {@code null} if the JWK did not state one. */
    public String declaredAlgorithm() {
        return declaredAlgorithm;
    }

    public PublicKey publicKey() {
        return publicKey;
    }

    /**
     * Build a verify-only {@link Algorithm} for the given JWS {@code alg}, checking that
     * the algorithm is compatible with this key's type. Asking an RSA key for an HMAC or
     * EC algorithm (or for {@code none}) throws, which is what blocks a token from
     * dictating an incompatible algorithm.
     */
    public Algorithm algorithmFor(String jwsAlgorithm) {
        if (jwsAlgorithm == null) {
            throw new JwtException("Token has no 'alg' to match against JWK " + kid);
        }
        if (declaredAlgorithm != null && !declaredAlgorithm.equals(jwsAlgorithm)) {
            throw new JwtException("Token alg '" + jwsAlgorithm + "' does not match JWK '"
                    + kid + "' declared alg '" + declaredAlgorithm + "'");
        }
        if ("RSA".equals(keyType)) {
            return switch (jwsAlgorithm) {
                case "RS256" -> Algorithms.rs256(publicKey);
                case "RS384" -> Algorithms.rs384(publicKey);
                case "RS512" -> Algorithms.rs512(publicKey);
                default -> throw new JwtException("Alg '" + jwsAlgorithm + "' is not valid for an RSA key");
            };
        }
        if ("EC".equals(keyType)) {
            return switch (jwsAlgorithm) {
                case "ES256" -> Algorithms.es256(publicKey);
                case "ES384" -> Algorithms.es384(publicKey);
                case "ES512" -> Algorithms.es512(publicKey);
                default -> throw new JwtException("Alg '" + jwsAlgorithm + "' is not valid for an EC key");
            };
        }
        throw new JwtException("Unsupported JWK key type: " + keyType);
    }

    // ---------- parsing ----------

    /** Build a {@link Jwk} from its parsed JSON object. */
    public static Jwk from(Map<String, Object> jwk) {
        String kty = str(jwk, "kty");
        String kid = str(jwk, "kid");
        String alg = str(jwk, "alg");
        if (kty == null) {
            throw new JwtException("JWK is missing 'kty'");
        }
        try {
            PublicKey key = switch (kty) {
                case "RSA" -> rsaKey(jwk);
                case "EC" -> ecKey(jwk);
                default -> throw new JwtException("Unsupported JWK key type: " + kty);
            };
            return new Jwk(kid, kty, alg, key);
        } catch (JwtException e) {
            throw e;
        } catch (Exception e) {
            throw new JwtException("Could not parse JWK " + kid, e);
        }
    }

    private static PublicKey rsaKey(Map<String, Object> jwk) throws Exception {
        BigInteger modulus = unsigned(req(jwk, "n"));
        BigInteger exponent = unsigned(req(jwk, "e"));
        return KeyFactory.getInstance("RSA")
                .generatePublic(new RSAPublicKeySpec(modulus, exponent));
    }

    private static PublicKey ecKey(Map<String, Object> jwk) throws Exception {
        String curve = switch (req(jwk, "crv")) {
            case "P-256" -> "secp256r1";
            case "P-384" -> "secp384r1";
            case "P-521" -> "secp521r1";
            default -> throw new JwtException("Unsupported EC curve: " + req(jwk, "crv"));
        };
        BigInteger x = unsigned(req(jwk, "x"));
        BigInteger y = unsigned(req(jwk, "y"));

        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(curve));
        ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);

        return KeyFactory.getInstance("EC")
                .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), ecSpec));
    }

    // ---------- export ----------

    /** Describe an RSA public key as a JWK (for publishing your own JWKS endpoint). */
    public static Jwk fromRsa(String kid, RSAPublicKey key) {
        return new Jwk(kid, "RSA", null, key);
    }

    /** Describe an EC public key as a JWK. */
    public static Jwk fromEc(String kid, ECPublicKey key) {
        return new Jwk(kid, "EC", null, key);
    }

    /** This key as a JWK JSON object (ordered), suitable for a JWKS document. */
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("kty", keyType);
        if ("RSA".equals(keyType)) {
            RSAPublicKey rsa = (RSAPublicKey) publicKey;
            map.put("n", Base64Url.encode(toUnsigned(rsa.getModulus())));
            map.put("e", Base64Url.encode(toUnsigned(rsa.getPublicExponent())));
        } else if ("EC".equals(keyType)) {
            ECPublicKey ec = (ECPublicKey) publicKey;
            int fieldBytes = (ec.getParams().getCurve().getField().getFieldSize() + 7) / 8;
            map.put("crv", curveName(fieldBytes));
            map.put("x", Base64Url.encode(toFixed(ec.getW().getAffineX(), fieldBytes)));
            map.put("y", Base64Url.encode(toFixed(ec.getW().getAffineY(), fieldBytes)));
        }
        map.put("use", "sig");
        if (kid != null) {
            map.put("kid", kid);
        }
        return map;
    }

    // ---------- helpers ----------

    private static String str(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v == null ? null : v.toString();
    }

    private static String req(Map<String, Object> m, String key) {
        String v = str(m, key);
        if (v == null) {
            throw new JwtException("JWK is missing required field '" + key + "'");
        }
        return v;
    }

    private static BigInteger unsigned(String base64Url) {
        return new BigInteger(1, Base64Url.decode(base64Url));
    }

    /** Big-endian magnitude with any sign byte removed (minimal, for RSA n/e). */
    private static byte[] toUnsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return bytes;
    }

    /** Big-endian magnitude left-padded to a fixed length (for EC x/y). */
    private static byte[] toFixed(BigInteger value, int length) {
        byte[] src = toUnsigned(value);
        if (src.length == length) {
            return src;
        }
        byte[] out = new byte[length];
        System.arraycopy(src, 0, out, length - src.length, Math.min(src.length, length));
        return out;
    }

    private static String curveName(int fieldBytes) {
        return switch (fieldBytes) {
            case 32 -> "P-256";
            case 48 -> "P-384";
            case 66 -> "P-521";
            default -> throw new JwtException("Unsupported EC field size: " + fieldBytes);
        };
    }
}
