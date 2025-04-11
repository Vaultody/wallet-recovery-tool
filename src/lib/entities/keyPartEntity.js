'use strict';

const BaseKeyPartEntity = require("./baseKeyPartEntity");
const BN = require("bn.js");
const {DOMAIN_PARAMS} = require("../enumerations/curve");
const crypto = require("crypto");
const bip39 = require("bip39");

class KeyPartEntity extends BaseKeyPartEntity {

    /**
     * @return {number}
     */
    getIndex() {
        return this.data['index'];
    }

    getData() {
        return Buffer.from(this.data['data'], "base64");
    }

    /**
     * @inheritDoc
     */
    _prepareData(data) {
        return {
            index: data.index,
            data: data.data,
        }
    }

    /**
     * @return {string[]}
     * @protected
     */
    _getRequiredAttributes() {
        return ['data', 'index'];
    }

    /**
     * @param {Buffer} ersPrivateKey
     * @param {string} curve
     * returns {BN}
     */
    recoverKeyShare(ersPrivateKey, curve) {
        const mnemonic = crypto.privateDecrypt({key: ersPrivateKey, oaepHash: "sha256"}, this.getData());

        return new BN(bip39.mnemonicToEntropy(mnemonic.toString()), 16).mod(DOMAIN_PARAMS[curve].n);
    }
}

module.exports = KeyPartEntity;
