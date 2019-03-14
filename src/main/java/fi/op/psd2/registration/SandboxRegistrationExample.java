package fi.op.psd2.registration;

public class SandboxRegistrationExample {
    public static void main(String [] args) {
        SandboxRegistrator registrator = new SandboxRegistrator();

        try {
            registrator.generateKeyMaterial();
            registrator.registerWithGeneratedCert();
            System.out.println("Registration succeeded.");
        } catch (Throwable ex) {
            System.out.println("Registration process failed: " + ex.getMessage());
        }
    }
}
