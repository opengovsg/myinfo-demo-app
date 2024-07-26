const fs = require('fs');
const crypto = require('crypto')
const _ = require('lodash')
const path = require('path');
const jose = require('node-jose');
const qs = require('node:querystring')
const jwt = require('jsonwebtoken')
require('dotenv').config();
const {
    PRIVATE_KEY
} = process.env;

const privateKeyPem = fs.readFileSync(
    path.resolve(__dirname, '../cert/key.pem'),
)

const privateKeyUTF = fs.readFileSync(
    path.resolve(__dirname, '../cert/key.pem'),
    'utf8'
)

const publicKey = fs.readFileSync(
    path.resolve(__dirname, '../cert/spcp.crt'),
    'utf8'
)


async function decryptSgIdData(body) {
    const result = {}

    const privateKey = await jose.JWK.asKey(PRIVATE_KEY, 'pem')
    const key = await jose.JWE.createDecrypt(privateKey).decrypt(body.key)

    const decryptedKey = await jose.JWK.asKey(key.plaintext, 'json')

    for (const [key, value] of Object.entries(body.data)) {
        const { plaintext } = await jose.JWE.createDecrypt(decryptedKey).decrypt(value)
        result[key] = plaintext.toString('ascii')
    }

    return result
}


function createHeaders(method, context, url, app_id, access_token = null) { 
    const timestamp = (new Date).getTime()
    const nonce = Math.floor(Math.random() * 100000)
    const defaultAuthHeaders = {
        "app_id": app_id, 
        "nonce": nonce,
        "signature_method": "RS256",
        "timestamp": timestamp,
    }

    const baseParams = Object.fromEntries(
        Object.entries(_.merge(defaultAuthHeaders, context)).sort(([k1], [k2]) => k1.localeCompare(k2)),
    )

    var baseParamsStr = qs.stringify(baseParams);
    baseParamsStr = qs.unescape(baseParamsStr)
    const baseString = method + "&" + url + "&" + baseParamsStr;
    const signature = crypto.createSign("RSA-SHA256")
      .update(baseString)
      .sign(privateKeyUTF, "base64");

    const token = access_token ? `,Bearer ${access_token}` : ""
    const authHeader = "PKI_SIGN app_id=\"" + app_id +
    "\",timestamp=\"" + timestamp +
    "\",nonce=\"" + nonce +
    "\",signature=\"" + signature +
    "\"" + token

    const headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cache-Control": "no-cache",
        "Authorization": authHeader,
    }

    return headers
}

async function decryptSingpassData(block) {
    const privateKey = await jose.JWK.asKey(privateKeyPem, 'pem')
    const decryptedBlock = await jose.JWE.createDecrypt(privateKey).decrypt(block)

    const signature = decryptedBlock.plaintext.toString()

    const jwsPayload = jwt.verify(signature, publicKey, {
        algorithms: ['RS256'],
    })
    return jwsPayload
}

function getProfileAndScope(token) {
    const jwsPayload = jwt.verify(token, publicKey, {
        algorithms: ['RS256'],
    })
    const scope = jwsPayload.scope.join(",")
    return {
        "attributes": scope,
        "uinfin": jwsPayload.sub
    }

}



module.exports = {
    decryptSgIdData,
    decryptSingpassData,
    createHeaders,
    getProfileAndScope
};