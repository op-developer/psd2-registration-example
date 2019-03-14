package fi.op.psd2.registration;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class EnvironmentConfig {

    public static final String TPP_REGISTRATION_REGISTER_URL = "tpp.registration.register.url";
    public static final String TPP_CLIENT_CERT_GENERATION_URL = "tpp.client.cert.generation.url";
    public static final String SSA_SOFTWARE_REDIRECT_URIS = "tpp.ssa.software.redirect.uris";
    public static final String SSA_SOFTWARE_ROLES = "tpp.ssa.software.roles";
    public static final String SSA_SOFTWARE_CLIENT = "tpp.ssa.software.client";
    public static final String TPP_API_KEY = "tpp.api.key";
    public static final String TPP_CN = "tpp.cn";
    public static final String SSA_SOFTWARE_CLIENT_URI = "tpp.ssa.software.client.uri";

    Properties config = new Properties();

    public EnvironmentConfig() {
        InputStream is;

        try {
            is = new FileInputStream("registration.properties");
        } catch (FileNotFoundException ex) {
            throw new RuntimeException(ex);
        }
        try {
            config.load(is);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public String getTppRegistrationRegisterUrl() {
        return getStringProperty(TPP_REGISTRATION_REGISTER_URL);
    }

    public String getTppClientCertGenerationUrl() {
        return getStringProperty(TPP_CLIENT_CERT_GENERATION_URL);
    }

    public String getSsaSoftwareClient() {
        return getStringProperty(SSA_SOFTWARE_CLIENT);
    }

    public String getTppApiKey() {
        return System.getProperty("apiKey", getStringProperty(TPP_API_KEY));
    }

    public String getTppCn() {
        return getStringProperty(TPP_CN);
    }

    public String getSsaSoftwareClientUri() {
        return getStringProperty(SSA_SOFTWARE_CLIENT_URI);
    }

    public String[] getSsaSoftwareRedirectUris() {
        return getStringArrayProperty(SSA_SOFTWARE_REDIRECT_URIS);
    }

    public String[] getSsaSoftwareRoles() {
        return getStringArrayProperty(SSA_SOFTWARE_ROLES);
    }

    public String getStringProperty(String key) {
        String value = config.getProperty(key);
        return value;
    }

    public String[] getStringArrayProperty(String key) {
        String[] value = config.getProperty(key).split(",");
        return value;
    }
}
