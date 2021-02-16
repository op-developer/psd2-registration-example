# PSD2 TPP registration example

This module contains Typescript code for:

1. Generating Certificates for MTLS and JWT Signing for OP PSD2 Sandbox environment and
2. Registering to OP's PSD2 Sandbox and Production environments.

For information on the details, see the source code and the [TPP setup page](https://op-developer.fi/p/psd2-tpp-setup).

## Prerequisites

- Latest version of NodeJS
- Typescript `npm i -g typescript`
- tslint `npm i -g tslint`
- ts-node `npm i -g ts-node`
- conf/env.json pre-filled with your organization's data
- Api Key: Register an app on OP Developer and subscribe to one or more PSD2 sandbox APIs. Add your api key to env.json attribute `api_key`.

### env.json

Replace following values in the conf/env.json to match your organization (refer to <https://op-developer.fi/p/psd2-tpp-setup#user-content-tpp-registration> for attribute details):

- `country`
- `redirect_uris`
- `tpp_id`
- `api_key`
- `public_jwks_url`
- `ssa.software_client_name`
- `ssa.software_client_uri`
- `ssa.software_redirect_uris`
- `ssa.org_name`
- `ssa.org_contacts`

## Running the app stand-alone

### Without pregenerated private JWKS (only for sandbox)

This option will generate suitable certificates & private jwks (stored in conf/privatejwks.json) for you for sandbox demo use using sandbox entry in env.json as attribute source.

```bash
$ npm i
$ npm run register-tpp
```

Upon successful request, you will first receive sandbox jwks that is in turn
utilized to send a signed registration request. Finally, response JSON as
depicted in [OP Developer
documentation](https://op-developer.fi/p/psd2-tpp-setup#user-content-tpp-registration)
is returned.

### With pregenerated private JWKS

Prerequisites:
- You have generated your own private JWKS and stored it as .json
- Your env.json contains attribute `public_jwks_url` with a valid url to your public JWKS.

```bash
$ npm i
$ npm run register-tpp privateJwksPath=/path/to/privatejwks.json
```

### Define environment

By adding 'environment' command-line argument, you can explicitly define which enviroment in env.json is used:

```bash
$ npm i
$ npm run register-tpp environment=prod
```

Without explicitly defined enviroment argument, the program will default to 'sandbox'.

## License

This project is licensed under the terms of the MIT license.
