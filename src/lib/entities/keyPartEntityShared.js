'use strict';

const BaseKeyPartEntity = require("./baseKeyPartEntity");
const BN = require("bn.js");
const {DOMAIN_PARAMS} = require("../enumerations/curve");
const curveUtils = require("../utils/curve");
const crypto = require("crypto");
const lagrange = require("../utils/lagrange");

class KeyPartEntity extends BaseKeyPartEntity {

    /**
     * @return {Object<string, BN>}
     */
    getValues() {
        return this.data['values'];
    }

    /**
     * @return {Object<string, Buffer>}
     */
    getEncryptedValues() {
        return this.data['encryptedValues'];
    }

    /**
     * @return {Buffer}
     */
    getCommitment() {
        return this.data['commitment'];
    }

    /**
     * @inheritDoc
     */
    _prepareData(data) {
        const values = {};
        for (const key in data['values']) {
            values[key] = new BN(Buffer.from(data['values'][key], 'base64'), 16);
        }

        const encryptedValues = {};
        for (const key in data['encrypted_values']) {
            encryptedValues[key] = Buffer.from(data['encrypted_values'][key], 'base64');
        }

        return {
            commitment: Buffer.from(data['commitment'], 'base64'),
            values: values,
            encryptedValues: encryptedValues,
        }
    }

    /**
     * @return {string[]}
     * @protected
     */
    _getRequiredAttributes() {
        return ['commitment', 'values', 'encrypted_values'];
    }

    /**
     * @param {Buffer} ersPrivateKey
     * @param {string} curve
     * returns {BN}
     */
    recoverKeyShare(ersPrivateKey, curve) {
        const domainParams = DOMAIN_PARAMS[curve];
        const keyPartValues = this.getValues();
        const encryptedValues = this.getEncryptedValues();
        const commitment = curveUtils.decodePoint(curve, this.getCommitment());
        const indices = [];
        const values = [];

        for (const key in keyPartValues) {
            values.push(keyPartValues[key]);
            indices.push(new BN(key));
        }

        let keyShare = null;
        for (const key in encryptedValues) {
            const encryptedValue = encryptedValues[key];
            const decryptedValue = crypto.privateDecrypt({key: ersPrivateKey, oaepHash: "sha256"}, encryptedValue);
            indices[indices.length] = new BN(key);
            values[values.length] = new BN(decryptedValue).mod(domainParams.n);

            const candidateKeyShare = lagrange.reconstruct(indices, values, domainParams.n);
            const candidateKeyShareCommitment = domainParams.g.mul(candidateKeyShare);

            if (commitment.eq(candidateKeyShareCommitment)) {
                keyShare = candidateKeyShare;
                break;
            }
        }

        if (keyShare === null) {
            throw new Error("Unable to recover share, recovery data encryptions did not match commitment")
        }

        return keyShare;
    }
}

module.exports = KeyPartEntity;
