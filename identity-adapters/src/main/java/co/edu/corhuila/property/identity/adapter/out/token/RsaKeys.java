package co.edu.corhuila.property.identity.adapter.out.token;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Reads the key pair from PEM (as openssl genpkey and openssl pkey -pubout write
 * it), and computes what the published copy of the public key needs.
 */
public final class RsaKeys {

    private RsaKeys() { }

    /** A PKCS#8 "PRIVATE KEY" PEM: JWT_PRIVATE_KEY or the content of JWT_PRIVATE_KEY_FILE. */
    public static RSAPrivateCrtKey readPrivate(String pem) {
        if (pem == null || !pem.contains("BEGIN PRIVATE KEY")) {
            throw new IllegalArgumentException("JWT private key is not a PKCS#8 PEM private key");
        }
        try {
            return (RSAPrivateCrtKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decode(pem)));
        } catch (GeneralSecurityException | ClassCastException e) {
            throw new IllegalArgumentException("JWT private key cannot be read", e);
        }
    }

    public static RSAPublicKey readPublic(String pem) {
        if (pem == null || !pem.contains("BEGIN PUBLIC KEY")) {
            throw new IllegalArgumentException("JWT public key is not a PEM public key");
        }
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decode(pem)));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("JWT public key cannot be read", e);
        }
    }

    /**
     * Fails fast when the two keys of the configuration are not one pair: the
     * service would sign tokens that no service, itself included, accepts.
     */
    public static void requirePair(RSAPrivateCrtKey privateKey, RSAPublicKey publicKey) {
        if (!privateKey.getModulus().equals(publicKey.getModulus())
                || !privateKey.getPublicExponent().equals(publicKey.getPublicExponent())) {
            throw new IllegalArgumentException("JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are not one key pair");
        }
    }

    /** The JWK thumbprint of the public key (RFC 7638): the kid of the tokens and of /jwks. */
    public static String keyId(RSAPublicKey key) {
        String canonical = "{\"e\":\"" + base64Url(key.getPublicExponent().toByteArray())
                + "\",\"kty\":\"RSA\",\"n\":\"" + base64Url(key.getModulus().toByteArray()) + "\"}";
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Base64url of an unsigned big-endian integer, without the sign byte (RFC 7518, 6.3.1). */
    public static String base64Url(byte[] signedBigEndian) {
        int skip = signedBigEndian.length > 1 && signedBigEndian[0] == 0 ? 1 : 0;
        byte[] unsigned = new byte[signedBigEndian.length - skip];
        System.arraycopy(signedBigEndian, skip, unsigned, 0, unsigned.length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(unsigned);
    }

    private static byte[] decode(String pem) {
        return Base64.getDecoder().decode(pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", ""));
    }
}
