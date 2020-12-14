package fi.op.psd2.registration;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import io.restassured.RestAssured;
import io.restassured.config.EncoderConfig;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.bouncycastle.util.encoders.Base64;
import org.json.JSONArray;
import org.json.JSONObject;
import sun.security.provider.X509Factory;

import java.io.*;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.concurrent.TimeUnit;

import static io.restassured.RestAssured.given;

public class SandboxRegistrator {

    private EnvironmentConfig env = new EnvironmentConfig();
    private String tppId;
    private String tppApiKey;
    private String registrationRequest;
    private Response response;
    private String jwkStr;
    private String tppClientCert;
    RSAPrivateCrtKey tppPrivateCertKey;
    private String keystore;
    private String keystorePassword;
    private String softwareClientName;
    ECPrivateKey ecPrivateKey;
    private String ecPrivateKeyKid;
    private String jwksPublicUrl;

    public SandboxRegistrator() {
        this.tppApiKey = env.getTppApiKey();
        this.softwareClientName = env.getSsaSoftwareClientName();
    }

    protected void generateKeyMaterial() throws Throwable {

        fetchJwks();
        extractsKeys();
        createP12KeystoreWithCertificateAndPrivateKey();

    }

    protected void registerWithGeneratedCert() throws Throwable {
        generateRegistrationRequest();
        register();
    }

    private void generateRegistrationRequest() throws Throwable {
        registrationRequest = PSD2Utils.generateSignedSSAJwt(env, this.tppId,
                this.softwareClientName, this.ecPrivateKey, this.ecPrivateKeyKid, this.jwksPublicUrl);
    }

    public void register() throws Throwable {

        response = given()
                .config(RestAssured.config().encoderConfig(EncoderConfig.encoderConfig().encodeContentTypeAs("application/jwt", ContentType.TEXT)))
                .trustStore(loadTruststore())
                .keyStore(this.keystore, this.keystorePassword)
                .log().all()
                .accept(ContentType.JSON)
                .header("Content-Type", "application/jwt")
                .header("x-api-key", this.tppApiKey)
                .body(registrationRequest)
                .when().post(env.getTppRegistrationRegisterUrl());
        response.then().log().all().assertThat().statusCode(201);
        System.out.println("tpp registration time: " + response.getTimeIn(TimeUnit.MILLISECONDS));

        BufferedWriter resultWriter = new BufferedWriter(new FileWriter("registration-result.txt"));
        resultWriter.write("registration: ");
        resultWriter.newLine();
        resultWriter.write(response.getBody().prettyPrint());
        resultWriter.newLine();
        resultWriter.write("ssaSigningKid: " + ecPrivateKeyKid);
        resultWriter.close();
    }

    private KeyStore loadTruststore() throws Exception {
        KeyStore trustStore = KeyStore.getInstance("pkcs12");
        trustStore.load(this.getClass().getResourceAsStream("/client-truststore.jks"),
                "whatever".toCharArray());
        return trustStore;
    }

    private void fetchJwks() {

        response = given()
                .log().all()
                .accept(ContentType.JSON)
                .header("x-api-key", this.tppApiKey)
                .when().post(env.getTppClientCertGenerationUrl()
                        + "?c=FI"
                        + "&cn=SANDBOX" + this.env.getTppCn());
        response.then().log().all().assertThat().statusCode(201);
        System.out.println("cert generation time: " + response.getTimeIn(TimeUnit.MILLISECONDS));
        this.tppId = getTppIdFromLocationHeader(response.getHeader("Location"));
        System.out.println("tppId is: " + this.tppId);
        jwkStr = response.getBody().print();
    }

    private String getTppIdFromLocationHeader(String locationHeader) {
        int startIndex = locationHeader.lastIndexOf('/') + 1;
        return locationHeader.substring(startIndex);
    }

    public void extractsKeys() throws Throwable {
        extractCertificateAndPrivateKey();
        extractSsaSigningKey();
    }

    private void extractSsaSigningKey() throws Throwable {
        JSONObject response = new JSONObject(jwkStr);
        JSONObject jwks = response.getJSONObject("privateJwks");
        JSONObject jwk = jwks.getJSONArray("keys").getJSONObject(1);

        ECKey.Builder builder = new ECKey.Builder(Curve.P_256, new Base64URL(jwk.getString("x")), new Base64URL(jwk.getString("y")));
        builder.d(new Base64URL(jwk.getString("d")));

        ecPrivateKey = builder.build().toECPrivateKey();
        ecPrivateKeyKid = jwk.getString("kid");
        jwksPublicUrl = response.getString("publicJwksUrl");

        String tppPrivateKeyStr = PSD2Utils.toPemString("PRIVATE KEY", ecPrivateKey.getEncoded());
        BufferedWriter privateKeyWriter = new BufferedWriter(new FileWriter("ssa-signing-key.pem"));
        privateKeyWriter.write(tppPrivateKeyStr);
        privateKeyWriter.close();
    }

    public void extractCertificateAndPrivateKey() throws Throwable {
        JSONObject response = new JSONObject(jwkStr);
        JSONObject jwks = response.getJSONObject("privateJwks");
        JSONObject jwk = jwks.getJSONArray("keys").getJSONObject(0);

        BigInteger nBigInt = new BigInteger(1, java.util.Base64.getUrlDecoder().decode(jwk.getString("n")));
        BigInteger dBigInt = new BigInteger(1, java.util.Base64.getUrlDecoder().decode(jwk.getString("d")));
        BigInteger eBigInt = new BigInteger(1, java.util.Base64.getUrlDecoder().decode(jwk.getString("e")));

        tppPrivateCertKey = PSD2Utils.createCrtKey(nBigInt, eBigInt, dBigInt);

        String tppPrivateKeyStr = PSD2Utils.toPemString("RSA PRIVATE KEY", tppPrivateCertKey.getEncoded());
        BufferedWriter privateKeyWriter = new BufferedWriter(new FileWriter("key.pem"));
        privateKeyWriter.write(tppPrivateKeyStr);
        privateKeyWriter.close();

        JSONArray certChain = jwk.getJSONArray("x5c");
        tppClientCert = certChain.getString(0);
        BufferedWriter clientCertWriter = new BufferedWriter(new FileWriter("client.crt"));
        clientCertWriter.write(PSD2Utils.toPemString("CERTIFICATE",  java.util.Base64.getMimeDecoder().decode(tppClientCert)));
        clientCertWriter.close();
    }

    private void createP12KeystoreWithCertificateAndPrivateKey() throws Throwable {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        this.keystorePassword = "test";
        char[] password = this.keystorePassword.toCharArray();
        ks.load(null, password);

        byte [] certDecoded = Base64.decode(tppClientCert.replaceAll(X509Factory.BEGIN_CERT + "\n", "").replaceAll("\n" + X509Factory.END_CERT + "\n", ""));
        Certificate cert = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certDecoded));

        KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(tppPrivateCertKey, new Certificate[]{cert});
        ks.setEntry("client", privateKeyEntry, new KeyStore.PasswordProtection(password));
        this.keystore = this.tppId + "-client.p12";
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(keystore);
            ks.store(fos, password);
        } finally {
            fos.close();
        }
    }
}
