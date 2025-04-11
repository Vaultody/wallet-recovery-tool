'use strict';

const {DOMAIN_PARAMS} = require("../enumerations/curve");
const crypto = require("crypto");
const xpubUtils = require('../utils/xpub');
const sjcl = require('sjcl');
const privateKeyTypeEnum = require("../enumerations/privateKeyType");
const sharingType = require("../enumerations/sharingType");

class RecoveryToolService {

    /**
     * @param {string} password
     * @return {{privateKey: string, publicKey: string}}
     */
    generateRsaKeyPair(password) {
        const options = {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'pkcs1',
                format: 'pem',
            },
            privateKeyEncoding: {
                type: 'pkcs1',
                format: 'pem',
            },
        };

        const {privateKey, publicKey} = crypto.generateKeyPairSync("rsa", options);
        const encryptedPrivateKey = sjcl.encrypt(password, privateKey, {ks: 256, mode: "gcm"});
        return {
            publicKey: publicKey,
            privateKey: encryptedPrivateKey,
        }
    }

    /**
     * @param {RecoveryDataEntity} recoveryData
     * @param {Buffer} privateKeyBuffer
     * @param {string} privateKeyType
     * @param {string|null} password
     * @return {string}
     */
    recoverXpriv(recoveryData, privateKeyBuffer, privateKeyType, password = null) {
        let rsaPrivateKey;
        try {
            rsaPrivateKey = privateKeyType.includes(privateKeyTypeEnum.SJCL_ENCRYPTED)
                ? sjcl.decrypt(password, privateKeyBuffer.toString())
                : privateKeyBuffer.toString();
        } catch (e) {
            throw new Error("Invalid password!");
        }

        const privateKey = recoveryData.recoverPrivateKey(rsaPrivateKey);
        const chainCode = recoveryData.recoverChainCode(rsaPrivateKey);

        return xpubUtils.generateXpriv({curve: recoveryData.getCurve(), chainCode, key: privateKey});
    }

}

module.exports = RecoveryToolService;
