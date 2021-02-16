import got from 'got';
import { JWK, JWKS, JWS, JWT } from 'jose';
import * as fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import { getCertificates, CertificateResponse, findOrganizationIdFromCertificate, x5cToCert } from './certificate-utils';
import * as https from 'https';

interface RegistrationRequest {
    iat: number;
    exp: number;
    aud: string;
    jti: string;
    redirect_uris: string[];
    grant_types: string[];
    software_statement: string;
}

interface RegistrationResponse {
    client_id: string;
    client_id_issued_at: number;
    client_secret: string;
    client_secret_expires_at: number;
    api_key: string;
    client_name: string;
    redirect_uris: string[];
    grant_types: string[];
    software_id: string;
    scope: string;
    jwks_endpoint: string;
    software_roles: string[];
}

interface OrgContact {
    name: string | undefined;
    email: string;
    phone: string | undefined;
    type: string | undefined;
}

interface SoftwareStatement {
    iss: string;
    iat: number;
    exp: number;
    jti: string;
    software_client_id: string;
    software_roles: string[];
    software_jwks_endpoint: string;
    software_jwks_revoked_endpoint: string;
    software_client_name: string;
    software_redirect_uris: string[];
    software_client_uri: string;
    org_name: string;
    org_id: string;
    org_contacts: OrgContact[];
}

interface Args {
    environment: string | undefined;
    privateJwksPath: string | undefined;
}

const PRIVATE_JWKS_PATH = './conf/privatejwks.json';

const getArgs = () : Args => {
    return process.argv
    .slice(2)
    .map(arg => arg.split('='))
    .reduce((args, [value, key]) => {
        args[value] = key;
        return args;
    }, {}) as Args;
}

const env = JSON.parse(fs.readFileSync('conf/env.json', 'utf8').toString())[getArgs().environment ?? 'sandbox'];

const getMTLSAgent = (mtlsKey: Buffer, mtlsCert: Buffer) => {
    const httpsAgent = new https.Agent({
        cert: mtlsCert,
        key: mtlsKey,
        rejectUnauthorized: true,
    });
    return httpsAgent;
};

const constructSSA = (jwk: JWK.Key, jwksUrl: string, orgId: string): string => {
    const ssa: SoftwareStatement = {...env.ssa};
    ssa.iss = env.tpp_id;
    ssa.iat = Math.round(new Date().getTime() / 1000) - 100;
    ssa.exp = ssa.iat + 20000;
    ssa.jti = uuidv4();
    ssa.software_jwks_endpoint = jwksUrl;
    ssa.software_client_id = uuidv4();
    ssa.org_id = orgId.substr(3); // cut off PSD prefix
    console.log(`----BEGIN SOFTWARE STATEMENT----\n${JSON.stringify(ssa, null, 2)}\n----END SOFTWARE STATEMENT----\n\n`);
    return JWS.sign(ssa, jwk, { kid: jwk.kid });
};

const constructRequest = (jwk: JWK.Key, software_statement: string): string => {
    const iat: number = Math.round(new Date().getTime() / 1000) - 100;
    const exp: number = iat + 20000;
    const request: RegistrationRequest = {
        iat,
        exp,
        aud: env.aud,
        jti: uuidv4(),
        redirect_uris: env.redirect_uris,
        grant_types: env.grant_types,
        software_statement
    };
    console.log(`----BEGIN REGISTRATION REQUEST----\n${JSON.stringify(request, null, 2)}\n----END REGISTRATION REQUEST----\n\n`);
    return JWT.sign(request, jwk);
};

const getPublicJwks = async (url: string) : Promise<JWKS.KeyStore>=> {
    console.log(`----BEGING JWKS REQUEST----\n${url}\n----END JWKS REQUEST----`);
    try {
        const response = await got(url, {
            headers: {
                'Accept': 'application/json'
            },
            timeout: 5000, // ms
        });
        return JWKS.asKeyStore(JSON.parse(response.body));
    } catch (e) {
        console.error(`Error while fetching public jwks: ${e}`);
        throw e;
    }
}

const validate = async (jwt: string, jwks: JWKS.KeyStore): Promise<void> => {
    try {
        JWT.verify(jwt, jwks, {
            algorithms: ['ES256', 'RS256', 'PS256'],
            clockTolerance: '120s',
            maxTokenAge: '600s',
            complete: true,
        });
    } catch (e) {
        console.error(`JWT validation error(): ${e}`);
        throw e;
    }

}

const register = async (body: string, apikey: string, agent: any): Promise<RegistrationResponse> => {
    try {
        const response = await got.post(env.registration_url, {
            agent: {
                http: agent,
                https: agent
            },
            headers: {
                'x-api-key': apikey,
                'Content-Type': 'application/jwt',
                'Accept': 'application/json'
            },
            body
        });
        return JSON.parse(response.body) as RegistrationResponse;
    } catch (e) {
        console.error(`Registration error: ${e}`);
        throw e;
    }
};



const main = async () => {

    let publicJwksUrl: string = '';
    let privateJwksPath: string = getArgs().privateJwksPath;
    try {
        if (!privateJwksPath) {
            privateJwksPath = PRIVATE_JWKS_PATH;
            const certificateResponse: CertificateResponse = await getCertificates(env.certificate_url, env.api_key, env.country, env.tpp_id);
            fs.writeFileSync(PRIVATE_JWKS_PATH, JSON.stringify(certificateResponse));
            publicJwksUrl = certificateResponse.publicJwksUrl
        }
        else {
            publicJwksUrl = env.public_jwks_url;
        }
        const publicJwks = await getPublicJwks(publicJwksUrl);
        const privateJwks = JSON.parse(fs.readFileSync(privateJwksPath, 'utf8').toString())['privateJwks'];
        const privateJwk =  JWKS.asKeyStore(privateJwks, {calculateMissingRSAPrimes: true}).get({alg: 'RS256'});
        const mtlsKey = Buffer.from(privateJwk.toPEM(true));
        const mtlsCert = Buffer.from(x5cToCert(privateJwk.x5c[0]));

        const orgId = findOrganizationIdFromCertificate(mtlsCert.toString());

        const ssa: string = constructSSA(privateJwk, publicJwksUrl, orgId);
        const registrationRequest: string = constructRequest(privateJwk, ssa);
        await validate(ssa, publicJwks);
        await validate(registrationRequest, publicJwks);
        const registrationResponse: RegistrationResponse = await register(registrationRequest, env.api_key, getMTLSAgent(mtlsKey, mtlsCert));
        console.log(`----BEGIN REGISTRATION RESPONSE----\n${JSON.stringify(registrationResponse, null, 2)}\n----END REGISTRATION RESPONSE----\n`);
    }
    catch (e) {
        console.error(e);
        process.exit(1);
    }
};

main();
