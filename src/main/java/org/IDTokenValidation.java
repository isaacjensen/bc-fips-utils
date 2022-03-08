package org;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPublicKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

public class IDTokenValidation {
    // Sample id_token that needs validation. This is probably the only field you
    // need to change to test your id_token.
    // If it doesn't work, try making sure the MODULUS and EXPONENT constants are
    // what you're using, as detailed below.
    public static final String id_token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJnb0dYUUxhRTA3cEFBXzBEMm9BLWZEbzBCVUtJLWRYZDByYVBpRlBUWnlJIn0.eyJleHAiOjE2NDY3MzYxNTAsImlhdCI6MTY0NjcwMDE1MCwiYXV0aF90aW1lIjowLCJqdGkiOiJmY2ExZTBmZS1hM2M4LTQyYWEtOTMwZS02ZGFiNzlhMDdhZTkiLCJpc3MiOiJodHRwczovL3VhbS5rZXljbG9hay5pYW1yYmFjLmNvbS9hdXRoL3JlYWxtcy9JQU0iLCJhdWQiOiJQb0NDbGllbnQiLCJzdWIiOiIxMDFkYWQyOS1mYWYyLTRkMWQtYjg3OS04MGE4ZWZkMGNhN2EiLCJ0eXAiOiJJRCIsImF6cCI6IlBvQ0NsaWVudCIsImF0X2hhc2giOiJFUWFpYkltNmZyZjR3b1h5WjdCeTRRIiwiYWNyIjoiMSIsImxvZ2luX2hpbnQiOiJzZXJ2aWNlLWFjY291bnQtcG9jY2xpZW50IiwiY2xpZW50SG9zdCI6IjE2MS42OS4yMy4yNCIsImNsaWVudElkIjoiUG9DQ2xpZW50IiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJpZHAiOiIwb2FlaTZiNGdrOGtlQTBrbzBoNyIsImdyb3VwcyI6W10sInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC1wb2NjbGllbnQiLCJjbGllbnRBZGRyZXNzIjoiMTYxLjY5LjIzLjI0In0.QGrYIrG0AvMgw94SpSfrgxkCrqEf7XP10GBGu-0cXT3ksQdqPAzjU96C4t8kdvMyuGMsgPqjFbsBspQy3-BMFLio13St8yiqNs3NqTDDuHdshQqAd1Sv6oQ9LRgUMFV9L5ZEyoYKVGGl4OdCPeTFs92gEqc1QR1BzePmHj3eVWd5KVxgfAYbTIclTdTUrxS98wXChHf37QvwCMnIQpLMWSnl8DGr5g_7_dQn5lDCMYtH2WdsGC5rzvhb4xzXChZ8td89QlPWpm7eL7riDdyZSwLuflJiIentZZT0LCMWCxOv-XTAKwcK_RnBybtI7m-F6UIBzRFhKcCzJBkvtWjhaw";
    public static final String[] id_token_parts = id_token.split("\\.");

    // Constants that come from the keys your token was signed with.
    // Correct values can be found from using the "kid" value and looking up the "n
    // (MODULUS)" and "e (EXPONENT)" fields
    // at the following url: https://login.salesforce.com/id/keys
    // MAJOR NOTE: This url will work for 90% of your use cases, but for the other
    // 10%
    // you'll need to make sure you get the "kid" value from the instance url that
    // the api responses from Salesforce suggest for your token, as the kid values
    // *will* be different.
    // e.g. Some users would need to get their kid values from
    // https://na44.salesforce.com/id/keys for example.
    // The following 2 values are hard coded to work with the "kid=196" key values.
    public static final String EXPONENT = "AQAB";
    public static final String MODULUS = "iYMh26U1IX7EhBT3GN2yXJOcJWfglG0vX7J3Fv_HzdfIWWDrrBxXgQQElJEQvzJgDCLyRmUZcaGftyMs_e0DV7-XxRIXBjLAqVJfZu1ERV8hf_8XBJpkuZ1S6ehDMI04041Abt8au74E4Z4XfAS3UwhSo-LrnKm7i9zztQdzzzw0XMFLipyrBeu3oOn8j17TOStioPK-SwHtS7_JJ3jLXk-AWdGAb86TwjBH74u24XcVUZuLJSHHPogcBW4nolWA5PGNzFRlUVOlAjHxRcZ1VO9sR_ogLMkDpJl-AqQokmKo2HU4v5PmjbJULZjjhtmVO3LzZMi3v10ROXPvAmRYBw";

    public static final String ID_TOKEN_HEADER = base64UrlDecode(id_token_parts[0]);
    public static final String ID_TOKEN_PAYLOAD = base64UrlDecode(id_token_parts[1]);
    public static final byte[] ID_TOKEN_SIGNATURE = base64UrlDecodeToBytes(id_token_parts[2]);

    public static String base64UrlDecode(String input) {
        byte[] decodedBytes = base64UrlDecodeToBytes(input);
        String result = new String(decodedBytes, StandardCharsets.UTF_8);
        return result;
    }

    public static byte[] base64UrlDecodeToBytes(String input) {
        Base64 decoder = new Base64(-1, null, true);
        byte[] decodedBytes = decoder.decode(input);

        return decodedBytes;
    }

    public static void main(String args[]) throws CertificateException, IOException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleFipsProvider());
        Security.addProvider(new BouncyCastleJsseProvider());
        dumpJwtInfo();
        validateToken(true); // true for fips providers, false for regular Java
    }

    public static void dump(String data) {
        System.out.println(data);
    }

    public static void dumpJwtInfo() {
        dump(ID_TOKEN_HEADER);
        dump(ID_TOKEN_PAYLOAD);
    }

    public static void validateToken(boolean fips) throws CertificateException, IOException, NoSuchProviderException {
        // TODO UNCOMMENT BELOW TO GENERATE PUBLIC KEY VIA x5c
        PublicKey publicKey = getPublicKeyFromCert("MIIClTCCAX0CBgF+4mvcLzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANJQU0wHhcNMjIwMjEwMDY1NTI2WhcNMzIwMjEwMDY1NzA2WjAOMQwwCgYDVQQDDANJQU0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCJgyHbpTUhfsSEFPcY3bJck5wlZ+CUbS9fsncW/8fN18hZYOusHFeBBASUkRC/MmAMIvJGZRlxoZ+3Iyz97QNXv5fFEhcGMsCpUl9m7URFXyF//xcEmmS5nVLp6EMwjTjTjUBu3xq7vgThnhd8BLdTCFKj4uucqbuL3PO1B3PPPDRcwUuKnKsF67eg6fyPXtM5K2Kg8r5LAe1Lv8kneMteT4BZ0YBvzpPCMEfvi7bhdxVRm4slIcc+iBwFbieiVYDk8Y3MVGVRU6UCMfFFxnVU72xH+iAsyQOkmX4CpCiSYqjYdTi/k+aNslQtmOOG2ZU7cvNkyLe/XRE5c+8CZFgHAgMBAAEwDQYJKoZIhvcNAQELBQADggEBADE5gy0UlfFj+5SuttQh48352HW4JYMDxcVa1lJufBcumpeqNSx7zA4vlLJoL74yjvdvEmLAMF0fzOPYm1GGbv4IwEx8AI7zBxvoMF5DU17E+TmDgDRdI9wIBCQrFXGgfQiDED/3ZDYpleAgimOw9gEW6L0dptSBj+QGOdHzflhJJKN1PZZjjeY+5/Lh3kqVGnQZtTP0qWip/ay4s8I40QRWOTIvne7W/YE1rkm7mDfYI3DIqHGNwsxk01pa9lKWVt+nosfo8pxBzepkat3NfiKHAReScfvI2Mt4FLE/0Sqe/VAuFUAJdEkYFrRiPGiLSIL2C2D6VzRWnYdu1+WtLrk=", fips);
        // TODO UNCOMMMENT TO GENERATE PUBLIC KEY VIA MODULUS/EXPONENT
        //PublicKey publicKey = getPublicKey(MODULUS, EXPONENT, fips);

        byte[] data = (id_token_parts[0] + "." + id_token_parts[1]).getBytes(StandardCharsets.UTF_8);

        try {
            boolean isSignatureValid = verifyUsingPublicKey(data, ID_TOKEN_SIGNATURE, publicKey, fips);
            System.out.println("isSignatureValid (fips = " + fips + "): " + isSignatureValid);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

    }

    public static PublicKey getPublicKey(String MODULUS, String EXPONENT, boolean fips) {
        byte[] nb = base64UrlDecodeToBytes(MODULUS);
        byte[] eb = base64UrlDecodeToBytes(EXPONENT);
        BigInteger n = new BigInteger(1, nb);
        BigInteger e = new BigInteger(1, eb);

        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(n, e);
        try {
            PublicKey publicKey;
            if (fips) {
                publicKey = KeyFactory.getInstance("RSA", "BCFIPS").generatePublic(rsaPublicKeySpec);
            } else {
                publicKey = KeyFactory.getInstance("RSA").generatePublic(rsaPublicKeySpec);
            }
            return publicKey;
        } catch (Exception ex) {
            throw new RuntimeException("Cant create public key", ex);
        }
    }

    private static boolean verifyUsingPublicKey(byte[] data, byte[] signature, PublicKey pubKey, boolean fips)
            throws GeneralSecurityException {
        Signature sig;
        if (fips) {
            sig = Signature.getInstance("SHA256withRSA", "BCFIPS"); // Equivalent to 'RS256' from KC
        } else {
            sig = Signature.getInstance("SHA256withRSA"); // Equivalent to 'RS256' from KC
        }

        sig.initVerify(pubKey);
        sig.update(data);
        return sig.verify(signature);
    }

    public static PublicKey getPublicKeyFromCert(String x5c, boolean fips)
            throws CertificateException, IOException, CertificateException, NoSuchProviderException {
        System.out.println(" x5c =" + x5c);
        String stripped = x5c.replaceAll("-----BEGIN (.*)-----", "");
        stripped = stripped.replaceAll("-----END (.*)-----", "");
        stripped = stripped.replaceAll("\r\n", "");
        stripped = stripped.replaceAll("\n", "");
        stripped.trim();
        System.out.println(" stripped =" + stripped);
        byte[] keyBytes = Base64.decodeBase64(stripped);
        CertificateFactory fact;
        if (fips) {
            fact = CertificateFactory.getInstance("X.509", "BCFIPS");
        } else {
            fact = CertificateFactory.getInstance("X.509");
        }
        X509Certificate cer = (X509Certificate) fact.generateCertificate(new ByteArrayInputStream(keyBytes));
        return cer.getPublicKey();

    }
}
