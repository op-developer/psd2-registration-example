# TPP Registration Example Code For Sandbox

This module contains Java code for 
1. Generating Certificates for MTLS and JWT Signing and 
2. Registering to OP's PSD2 Sandbox.

For information on the details, see the source code and the [TPP setup page](https://op-developer.fi/p/tpp-setup).

## Pre-requisities

- Java 11
- Maven
- Api Key: Register an app on OP Developer and subscribe to one or more PSD2 sandbox APIs. The API key is the value labeled APP_API_KEY.
- Fill in the required values in registration.properties (in the root directory of this project).

### Registration.properties

| Key | Explanation | Example value|
|-|-|-|
| tpp.registration.register.url | URI of the registration service. Only change this if you know the service URI has changed. | https://mtls-apis.psd2-sandbox.op.fi/tpp-registration/register |
| tpp.client.cert.generation.url | URI of the certificate generation service (incl. query marker "?"). Only change this value if you know the URI has changed. | https://sandbox.apis.op-palvelut.fi/oop-test-client-certs-psd2/v1/client-cert? |
| tpp.ssa.software.redirect.uris | The redirect URIs you want to register for your application. A comma-separated list of redirect URIs. These URIs do not have to match the values you may have provided on OP Developer. | https://localhost:8181,https://localhost:8080 |
| tpp.ssa.software.roles | PSD2 license roles available to you. A comma-separated list of roles. In sandbox, you man choose whichever roles you like. | AIS,PIS,CPBII |
| tpp.ssa.software.client | Name of your software client. Choose this as you wish. | Banklify.io |
| tpp.ssa.software.client.uri | Home domain of your software client. | https://example.com |
| tpp.api.key | API key of your client app. Obtained from OP Developer after client app registration. | fejw019ghawbv78oatuio |
| tpp.cn | Common Name of the TPP company. | Banklify.io |

## Getting started

1. Clone the repository and install the required dependencies
2. Build and run the project

```bash
mvn clean package
java -jar target/oop-registration-example-fat.jar
```

## Results

After successful registration, you will find four new files in the project directory.

| Filename | Explanation |
|-|-|
| client.crt | This is your client certificate, emulating QWAC. Present this any time you want to establish a mutually authenticated TLS connection. |
| key.pem | Private key corresponding to the certificate in client.crt. Used for encrypting traffic and must be used when establishing mutually authenticated TLS. |
| OP-TEST-TPP-\<generated-tpp-id\>-client.p12 | P12 keystore. Password and passphrase will be "test" unless you modify the code to change them. **Store the tpp id** as it is needed with authorization requests. |
| ssa-signing-key.pem | Your private key for signing JWTs, emulating QSEALC. Used for signing the SSA and registration JWT, but ALSO used for signing authorization request JWTs. Use ES256 asymmetric signing. |
| registration-result.txt | Details of the registration. This file will contain e.g. client_id, client_secret, ssaSigningKid,  and all other information related to your client app. |



For more information on certificates and PSD2 APIs see [OP Developer](https://op-developer.fi/psd2).


## License

This project is licensed under the terms of the MIT license.