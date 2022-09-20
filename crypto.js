const { subtle, JsonWebKey } = require('node:crypto').webcrypto;
const crypto = require('crypto').webcrypto;

// TODO export all the crypto params to a crypto.env file
async function genEcdhKey() {
    return await subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-384"
        },
        true,
        ["deriveKey"]
    );
}

 async function importEcdhJsonWebKey(jwkObj, keyUsages = []) {
    return await subtle.importKey(
        "jwk", //can be "jwk" (public or private), "raw" (public only), "spki" (public only), or "pkcs8" (private only)
        jwkObj,
        {   //these are the algorithm options
            name: "ECDH",
            namedCurve: "P-384", //can be "P-256", "P-384", or "P-521"
        },
        true, //whether the key is extractable (i.e. can be used in Key)
        keyUsages //"deriveKey" and/or "deriveBits" for private keys only (just put an empty list if importing a public key)
    )
}

async function deriveSecretKey(privateKey, publicKey) {
    return await subtle.deriveKey(
        {
            name: "ECDH",
            public: publicKey
        },
        privateKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}

async function exportJsonWebKey(key) {
    return await subtle.exportKey('jwk', key)
}

function convertJwkToJson(jwk) {
    return JSON.stringify(jwk)
}

function convertJsonToJwk(json) {
    return JSON.parse(json)
}

function getMessageEncoding(message) {
    let enc = new TextEncoder();
    return enc.encode(message);
}

function generateAESIV() {
    return crypto.getRandomValues(new Uint8Array(12));
}

async function encrypt(secretKey, iv, encoded) {

    return await subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        secretKey,
        encoded
    );
}

async function decrypt(secretKey, ciphertext, iv) {
    try {
        let decrypted = await subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            secretKey,
            ciphertext
        );

        let dec = new TextDecoder();
        return dec.decode(decrypted)
    } catch (e) {
        console.error(e)
        return `${e}`
    } 
}

module.exports = {
    genEcdhKey,
    importEcdhJsonWebKey,
    deriveSecretKey,
    exportJsonWebKey,
    convertJwkToJson,
    convertJsonToJwk,
    getMessageEncoding,
    generateAESIV,
    encrypt,
    decrypt
}