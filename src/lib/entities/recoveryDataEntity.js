'use strict';

const KeyPart = require("./keyPartEntity");
const KeyPartShared = require("./keyPartEntityShared");
const BaseEntity = require("./baseEntity");
const curveUtils = require("../utils/curve");
const lagrange = require("../utils/lagrange");
const {DOMAIN_PARAMS} = require("../enumerations/curve");
const sharingType = require("../enumerations/sharingType");
const BN = require("bn.js");
const crypto = require("crypto");

class RecoveryDataEntity extends BaseEntity {

    /**
     * @returns {Buffer}
     */
    getMasterChainCodeKey() {
        return this.data['masterChainCodeKey'];
    }

    /**
     * @returns {Buffer}
     */
    getMasterChainCode() {
        return this.data['masterChainCode'];
    }

    /**
     * @return {BaseKeyPartEntity[]}
     */
    getKeyParts() {
        return this.data['keyParts'];
    }

    /**
     * @returns {string}
     */
    getSharingType() {
        return this.data["sharingType"];
    }

    /**
     * @returns {number}
     */
    getVersion() {
        return this.data['version'];
    }

    /**
     * @returns {string}
     */
    getCurve() {
        return this.data["curve"];
    }

    /**
     * @inheritDoc
     */
    _prepareData(data) {
        const publicKey = Buffer.from(data["public_key"], 'base64');
        const curve = curveUtils.extractCurveFromPublicKey(publicKey);

        let keyParts;
        try {
            keyParts = data['key_parts'].map(keyPartData => new KeyPartShared(keyPartData));
        } catch (e) {
            keyParts = data['key_parts'].map(keyPartData => new KeyPart(keyPartData));
        }

        return {
            keyParts: keyParts,
            publicKey: publicKey,
            sharingType: data['sharing_type'],
            version: parseInt(data['version']),
            masterChainCode: Buffer.from(data['master_chain_code'], 'base64'),
            masterChainCodeKey: Buffer.from(data['master_chain_code_key'], 'base64'),
            curve: curve
        }
    }

    /**
     * @return {string[]}
     * @protected
     */
    _getRequiredAttributes() {
        return ['key_parts', 'public_key', 'sharing_type', 'version', 'master_chain_code', 'master_chain_code_key'];
    }

    /**
     * @inheritDoc
     */
    _validateAttributes(data) {
        super._validateAttributes(data);
        if (!Array.isArray(data['key_parts']) || data['key_parts'].length === 0) {
            throw new Error('key_parts attribute is empty or not an array');
        }
    }


    /**
     * @param {Buffer} ersPrivateKey
     * @return {string}
     */
    recoverPrivateKey(ersPrivateKey) {
        const domainParams = DOMAIN_PARAMS[this.getCurve()];
        const shares = [];
        const indices = [];
        for (const [index, part] of this.getKeyParts().entries()) {
            shares[index] = part.recoverKeyShare(ersPrivateKey, this.getCurve())
            indices[index] = new BN(index + 1);
        }

        let privateKey;
        switch (this.getSharingType()) {
            case sharingType.ADDITIVE:
                privateKey = shares.reduce((acc, val) => acc.add(val).mod(domainParams.n)).toString("hex");
                break;
            case sharingType.MULTIPLICATIVE:
                privateKey = shares.reduce((acc, val) => acc.mul(val).mod(domainParams.n)).toString("hex");
                break;
            case sharingType.SHAMIR:
                privateKey = lagrange.reconstruct(indices, shares, domainParams.n).toString("hex");
                break;
            default:
                throw new Error(`Unsupported sharing type: ${this.getSharingType()}`);
        }

        return privateKey.length % 2 ? `0${privateKey}` : privateKey.length < 64 ? `00${privateKey}` : privateKey;
    }

    /**
     * @param {string} ersPrivateKey
     * @return {string}
     */
    recoverChainCode(ersPrivateKey) {
        const masterChainCode = this.getMasterChainCode();
        const decryptedKey = crypto.privateDecrypt({key: ersPrivateKey, oaepHash: "sha256"}, this.getMasterChainCodeKey());

        const gcmTagSize = 16;
        const algorithm = "aes-256-gcm";
        const nonce = Buffer.alloc(12, '00', 'hex');
        const authTag = masterChainCode.subarray(masterChainCode.length - gcmTagSize);

        const decipher = crypto.createDecipheriv(algorithm, decryptedKey, nonce)
            .setAuthTag(authTag);
        const ciphertext = masterChainCode.subarray(0, masterChainCode.length - gcmTagSize);

        const decrypted = decipher.update(ciphertext);

        switch (this.getVersion()) {
            case 1:
                return decrypted.toString("hex");
            case 2:
            case 3:
                return Buffer.from(JSON.parse(decrypted).master_chain_code, "base64").toString("hex");
        }
    }
}

module.exports = RecoveryDataEntity;
