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
    strToUInt8Array,
    generateCounter
} = require("./crypto")

async function ecdhScenario() {
    // VOTING INITIALIZER SIDE
    // create voting protocol key
    let key = await genEcdhKey()

    // exporting voting public key to be sent to somewhere public
    let serverExportKey = await exportJsonWebKey(key.publicKey)
    let serverPubkeyStorage = convertJwkToJson(serverExportKey)
    // exporting voting private key to be stored somewhere safe
    serverExportKey = await exportJsonWebKey(key.privateKey)
    let serverPrivkeyStorage = convertJwkToJson(serverExportKey)

    // CLIENT (VOTER) SIDE: has only server pubkey as Json
    let vote = "resist"
    let jwkObj = convertJsonToJwk(serverPubkeyStorage)
    let votingPubkey = await importEcdhJsonWebKey(jwkObj)
    console.log(`assert imported voting pub key equals the initial one: ${votingPubkey === key.publicKey}`)

    let ephemeralKeyPair = await genEcdhKey()
    let clientSharedKey = await deriveSecretKey(ephemeralKeyPair.privateKey, votingPubkey)

    let counter = generateCounter()
    let counterStorage = counter.toString()
    let encodedMsg = getMessageEncoding(vote)
    let cipherArrBuffer = await encrypt(clientSharedKey, encodedMsg, counter)
    let ciphertext = new Uint8Array(cipherArrBuffer, 0, cipherArrBuffer.byteLength).toString()
    let clientExportKey = await exportJsonWebKey(ephemeralKeyPair.publicKey)
    let clientStorage = convertJwkToJson(clientExportKey)
    
    // at this point, we assume the priv key of the voting is published. 
    jwkObj = convertJsonToJwk(clientStorage)
    let clientPubKey = await importEcdhJsonWebKey(jwkObj)
    let serverPrivKey = await importEcdhJsonWebKey(convertJsonToJwk(serverPrivkeyStorage), ["deriveKey"])
    let serverSharedKey = await deriveSecretKey(serverPrivKey, clientPubKey)
    let decryptedMsg = await decrypt(clientSharedKey, strToUInt8Array(ciphertext), strToUInt8Array(counterStorage))
}

testKrypto()
