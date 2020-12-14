package fi.op.psd2.registration;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.UUID;

public class PSD2Utils {

    public static String toPemString(String header, byte[] encoded) throws IOException {
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(new PemObject(header, encoded));
        pemWriter.flush();
        return stringWriter.toString();
    }

    public static String generateSignedSSAJwt(EnvironmentConfig env, String tppId, String clientId, String clientName,
            ECPrivateKey generatedECPrivateKey, String kid, String publicJwksUrl) throws Throwable {

        final JWSSigner ssaSigner = new ECDSASigner(generatedECPrivateKey, Curve.P_256);
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).keyID(kid).build();
        final var ssaJson = createSoftwareStatement(tppId, clientId, clientName, publicJwksUrl, env);

        String ssa = buildSignedJwt(header, ssaJson, ssaSigner).serialize();

        final var ssaRequestJson = createSsaRequest((String[])ssaJson.get("software_redirect_uris"), ssa);
        String ssaRequest = buildSignedJwt(header, ssaRequestJson, ssaSigner).serialize();
        return ssaRequest;
    }

    private static final net.minidev.json.JSONArray getOrgContacts(EnvironmentConfig env) {
        final var orgContactsArray = new net.minidev.json.JSONArray();
        final var orgContact = new net.minidev.json.JSONObject();
        orgContact.put("name", "Sandbox Demo");
        orgContact.put("email", env.getSsaSoftwareEmail());
        orgContact.put("phone", "");
        orgContact.put("type", "Support");
        orgContactsArray.add(orgContact);
        return orgContactsArray;
    }

    private static final net.minidev.json.JSONObject createSoftwareStatement(String tppId, String clientId,
            String clientName, String jwksUrl, EnvironmentConfig env) {
        final var ssaJson = new net.minidev.json.JSONObject();
        ssaJson.put("iss", tppId);
        ssaJson.put("iat", Math.floor(System.currentTimeMillis()/1000));
        ssaJson.put("exp", Math.floor(System.currentTimeMillis()/1000 + 3155692600L));
        ssaJson.put("jti", UUID.randomUUID().toString());
        ssaJson.put("software_client_id", clientId);
        ssaJson.put("software_roles", env.getSsaSoftwareRoles());
        ssaJson.put("software_jwks_endpoint", jwksUrl);
        ssaJson.put("software_jwks_revoked_endpoint", jwksUrl);
        ssaJson.put("software_client_name", clientName);
        ssaJson.put("software_redirect_uris", env.getSsaSoftwareRedirectUris());
        ssaJson.put("software_client_uri", env.getSsaSoftwareClientUri());
        ssaJson.put("org_name", env.getTppCn());
        ssaJson.put("org_id", tppId);
        ssaJson.put("org_contacts", getOrgContacts(env));
        return ssaJson;
    }

    private static net.minidev.json.JSONObject createSsaRequest(String[] redirectUris, String ssa) {
        final var ssaRequestJson = new net.minidev.json.JSONObject();
        ssaRequestJson.put("iat", Math.floor(System.currentTimeMillis() / 1000));
        ssaRequestJson.put("exp", Math.floor(System.currentTimeMillis() / 1000) + 3155692600L);
        ssaRequestJson.put("aud", "https://op.fi/");
        ssaRequestJson.put("jti", UUID.randomUUID().toString());
        ssaRequestJson.put("redirect_uris", redirectUris);
        ssaRequestJson.put("grant_types", new String[] { "client_credentials", "authorization_code", "refresh_token" });
        ssaRequestJson.put("software_statement", ssa);
        return ssaRequestJson;
    }

    private static SignedJWT buildSignedJwt(JWSHeader header, net.minidev.json.JSONObject jwtClaims, JWSSigner jwtSigner) throws Throwable {
        SignedJWT signedJWT = new SignedJWT(header, JWTClaimsSet.parse(jwtClaims));
        signedJWT.sign(jwtSigner);
        return signedJWT;
    }

    public static RSAPrivateCrtKey createCrtKey(BigInteger n, BigInteger e, BigInteger d) throws Throwable {
        BigInteger p = findFactor(e, d, n);
        BigInteger q = n.divide(p);
        if (p.compareTo(q) > 1) {
            BigInteger t = p;
            p = q;
            q = t;
        }
        BigInteger exp1 = d.mod(p.subtract(BigInteger.ONE));
        BigInteger exp2 = d.mod(q.subtract(BigInteger.ONE));
        BigInteger coeff = q.modInverse(p);
        RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(n, e, d, p, q, exp1, exp2, coeff);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateCrtKey) kf.generatePrivate(keySpec);
    }

    private static BigInteger findFactor(BigInteger e, BigInteger d, BigInteger n) {
        BigInteger edMinus1 = e.multiply(d).subtract(BigInteger.ONE);
        int s = edMinus1.getLowestSetBit();
        BigInteger t = edMinus1.shiftRight(s);

        for (int aInt = 2; true; aInt++) {
            BigInteger aPow = BigInteger.valueOf(aInt).modPow(t, n);
            for (int i = 1; i <= s; i++) {
                if (aPow.equals(BigInteger.ONE)) {
                    break;
                }
                if (aPow.equals(n.subtract(BigInteger.ONE))) {
                    break;
                }
                BigInteger aPowSquared = aPow.multiply(aPow).mod(n);
                if (aPowSquared.equals(BigInteger.ONE)) {
                    return aPow.subtract(BigInteger.ONE).gcd(n);
                }
                aPow = aPowSquared;
            }
        }
    }
}
