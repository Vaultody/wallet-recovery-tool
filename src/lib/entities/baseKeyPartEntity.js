'use strict';

const BaseEntity = require("./baseEntity");

/**
 * Base class for all key part entities
 * Defines the interface that all key part implementations must follow
 * @abstract
 */
class BaseKeyPartEntity extends BaseEntity {
    /**
     * Constructor for BaseKeyPartEntity
     * @param {Object} data - The data for the entity
     * @throws {Error} When directly instantiated
     */
    constructor(data) {
        super(data);
        
        // Prevent direct instantiation of this abstract class
        if (this.constructor === BaseKeyPartEntity) {
            throw new Error('BaseKeyPartEntity is an abstract class and cannot be instantiated directly');
        }
    }

    /**
     * Recovers a key share using the provided ERS private key
     * @param {Buffer} ersPrivateKey - The ERS private key
     * @param {string} curve - The curve to use
     * @return {BN} The recovered key share
     * @throws {Error} When called directly on the base class
     * @abstract
     */
    recoverKeyShare(ersPrivateKey, curve) {
        throw new Error('Method recoverKeyShare must be implemented by subclass');
    }
}

module.exports = BaseKeyPartEntity; 