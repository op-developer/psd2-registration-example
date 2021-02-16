import { JSONWebKeySet } from 'jose';
import { Certificate } from '@fidm/x509';
import got from 'got';

export interface CertificateResponse {
    privateJwks: JSONWebKeySet;
    publicJwksUrl: string;
}

export const getCertificates = async (url: string, apikey: string, country: string, tppId: string): Promise<CertificateResponse> => {
    const searchParams = new URLSearchParams([['c', country], ['cn', tppId]]);
    try {
        const response = await got.post(url, {
            headers: {
                'x-api-key': apikey,
                'accept': 'application/json',
                'Content-Length': '0'
            },
            searchParams
        });
        return JSON.parse(response.body) as CertificateResponse;
    }
    catch (e) {
        console.error(e.response.body);
        throw e;
    }
};

const findFromCertificate = (what: string, where: string, attributes: boolean, certPEM: string) => {
    try {
        const cert: Certificate = Certificate.fromPEM(Buffer.from(certPEM, 'utf8'));
        try {
            if (attributes) {
                return cert[where].attributes.find(attribute => attribute.oid === what).value;
            }
            return cert[where][what];
        }
        catch (e) {
            const message = `Invalid or missing ${what} in certificate`;
            console.error(message);
            throw e;
        }
    }
    catch (e) {
        const message = 'Error parsing certificate';
        console.error(message);
        throw e;
    }
};

export const findOrganizationIdFromCertificate = (certificate: string) => {
    return findFromCertificate('2.5.4.97', 'subject', true, certificate);
};

export const x5cToCert = (cert: string) => {
    if (cert.indexOf('BEGIN CERTIFICATE') === -1 && cert.indexOf('END CERTIFICATE') === -1) {
        cert = cert.match(/.{1,64}/g).join('\n');
        cert = '-----BEGIN CERTIFICATE-----\n' + cert;
        cert = cert + '\n-----END CERTIFICATE-----\n';
        return cert;
    } else {
        return cert;
    }
};
