const {
    genEcdhKey,
    exportJsonWebKey, 
    convertJwkToJson, 
    convertJsonToJwk, 
    importEcdhJsonWebKey, 
    deriveSecretKey, 
    getMessageEncoding, 
    encrypt, 
    decrypt, 
    generateAESIV
} = require("./crypto")

async function testKrypto() {
    // WEB-APP SIDE
    // create voting key
    let key = await genEcdhKey()

    // exporting voting key to be sent to somewhere public
    let serverExportKey = await exportJsonWebKey(key.publicKey)
    let serverPubkeyStorage = convertJwkToJson(serverExportKey)
    serverExportKey = await exportJsonWebKey(key.privateKey)
    let serverPrivkeyStorage = convertJwkToJson(serverExportKey)

    // CLIENT SIDE: has no idea of the server priv key, has only server pubkey as JWK
    let review = "test vote"
    let jwkObj = convertJsonToJwk(serverPubkeyStorage)
    let votingPubkey = await importEcdhJsonWebKey(jwkObj)

    let ephemeralKeyPair = await genEcdhKey()
    let clientSharedKey = await deriveSecretKey(ephemeralKeyPair.privateKey, votingPubkey)

    let iv = generateAESIV().toString()
    let encodedMsg = getMessageEncoding(review)
    let ciphertext = await encrypt(clientSharedKey, iv, encodedMsg)
    let clientExportKey = await exportJsonWebKey(ephemeralKeyPair.publicKey)
    let clientStorage = convertJwkToJson(clientExportKey)

    // WEB-APP SIDE: has the encrypted msg, JWK of the sender and the IV to the AES-GCM encryption
    jwkObj = convertJsonToJwk(clientStorage)
    let clientPubKey = await importEcdhJsonWebKey(jwkObj)
    let serverPrivKey = await importEcdhJsonWebKey(convertJsonToJwk(serverPrivkeyStorage), ["deriveKey"])
    let serverSharedKey = await deriveSecretKey(serverPrivKey, clientPubKey)
    let decryptedMsg = await decrypt(serverSharedKey, ciphertext, iv)
}

testKrypto()