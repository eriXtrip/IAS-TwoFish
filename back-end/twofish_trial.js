"use strict";

/**
 * Twofish class implementing the Twofish encryption algorithm in CBC mode.
 * The class supports encryption and decryption using a key and initialization vector.
 */
class TwofishCBC {
    /**
     * @param {string} keyString The key used for encryption and decryption.
     * @param {string} ivString The initialization vector (must be 16 bytes).
     */
    constructor(keyString, ivString) {
        this.BLOCK_SIZE = 16; // Block size in bytes (128 bits)
        this.rounds = 16; // Number of rounds for encryption
        
        // Convert key and IV to byte arrays
        this.key = this.createKey(this.strToUTF8Arr(keyString));
        this.iv = this.strToUTF8Arr(ivString);
        
        // Validate IV length
        if (this.iv.length !== this.BLOCK_SIZE) {
            throw new Error("Initialization Vector must be 16 bytes long");
        }
        
        // Generate S-boxes and subkeys
        this.S = this.generateSBoxes(this.key);
        this.subkeys = this.keySchedule(this.key);
    }

    /**
     * Checks if a variable is an array or Uint8Array.
     */
    isAnArray(variable) {
        return Array.isArray(variable) || 
               Object.prototype.toString.call(variable) === "[object Uint8Array]";
    }

    /**
     * Converts a UTF-8 byte array to a string.
     */
    UTF8ArrToStr(byteArray) {
        return new TextDecoder().decode(new Uint8Array(byteArray));
    }

    /**
     * Converts a string to a UTF-8 byte array.
     */
    strToUTF8Arr(string) {
        const encoder = new TextEncoder();
        return Array.from(encoder.encode(string));
    }

    /**
     * Generates key-dependent S-boxes for substitution.
     */
    generateSBoxes(key) {
        const S = [[], [], [], []];
        for (let i = 0; i < 256; i++) {
            for (let j = 0; j < 4; j++) {
                S[j][i] = (i ^ key[(j + i) % key.length]) & 0xff;
            }
        }
        return S;
    }

    /**
     * Key schedule generation for round keys.
     */
    keySchedule(key) {
        const subkeys = [];
        for (let i = 0; i < 40; i++) {
            subkeys.push((key[i % key.length] + i * 0x9e3779b9) >>> 0);
        }
        return subkeys;
    }

    /**
     * Creates a 128-bit key from the input key array.
     */
    createKey(keyArray) {
        if (!this.isAnArray(keyArray)) throw "Key must be an array";
        while (keyArray.length < this.BLOCK_SIZE) keyArray.push(0);
        return keyArray.slice(0, this.BLOCK_SIZE);
    }

    /**
     * Applies whitening to the data block using the round subkeys.
     */
    applyWhitening(dataBlock, subkeys, offset = 0) {
        return dataBlock.map(
            (byte, index) => byte ^ (subkeys[offset + index] & 0xff)
        );
    }

    /**
     * F-function for the Feistel network.
     */
    fFunction(r, sBox, roundKey) {
        return (r ^ sBox[roundKey % sBox.length]) ^ roundKey;
    }

    /**
     * Performs one round of encryption.
     */
    encryptionRounds(dataBlock) {
        const subkeys = this.subkeys;
        const sBox = this.S;

        let left = dataBlock.slice(0, 8);
        let right = dataBlock.slice(8, 16);

        for (let round = 0; round < 16; round++) {
            let fOut = right.map((r, i) => this.fFunction(r, sBox, subkeys[round]));
            let newRight = left.map((l, i) => l ^ fOut[i % fOut.length]);
            
            left = right;
            right = newRight;
        }

        return [...left, ...right];
    }

    /**
     * Performs one round of decryption.
     */
    decryptionRounds(block) {
        const subkeys = this.subkeys;
        const sBox = this.S;

        let left = block.slice(0, 8);
        let right = block.slice(8, 16);

        for (let round = 15; round >= 0; round--) {
            let fOut = left.map((l, i) => this.fFunction(l, sBox, subkeys[round]));
            let newLeft = right.map((r, i) => r ^ fOut[i % fOut.length]);
            right = left;
            left = newLeft;
        }

        return [...left, ...right];
    }

    /**
     * XORs two blocks of data.
     */
    xorBlocks(block1, block2) {
        return block1.map((byte, i) => byte ^ block2[i]);
    }

    /**
     * Encrypts a block of data in CBC mode.
     */
    encryptBlock(dataBlock, previousBlock) {
        // XOR with previous ciphertext block (or IV for first block)
        const xoredBlock = this.xorBlocks(dataBlock, previousBlock);
        
        // Apply input whitening
        const whitenedBlock = this.applyWhitening(xoredBlock, this.subkeys, 0);
        
        // Perform encryption rounds
        const encryptedBlock = this.encryptionRounds(whitenedBlock);
        
        // Apply output whitening
        return this.applyWhitening(encryptedBlock, this.subkeys, 4);
    }

    /**
     * Decrypts a block of data in CBC mode.
     */
    decryptBlock(dataBlock, previousBlock) {
        // Apply output whitening (reverse order)
        const unwhitenedBlock = this.applyWhitening(dataBlock, this.subkeys, 4);
        
        // Perform decryption rounds
        const decryptedBlock = this.decryptionRounds(unwhitenedBlock);
        
        // Apply input whitening (reverse order)
        const whitenedBlock = this.applyWhitening(decryptedBlock, this.subkeys, 0);
        
        // XOR with previous ciphertext block (or IV for first block)
        return this.xorBlocks(whitenedBlock, previousBlock);
    }

    /**
     * Encrypts the input text using CBC mode.
     */
    encrypt(plainText) {
        const plainTextArray = this.strToUTF8Arr(plainText);
        const encryptedResult = [];
        let previousBlock = this.iv; // Start with IV

        // Process each block
        for (let i = 0; i < plainTextArray.length; i += this.BLOCK_SIZE) {
            const dataBlock = plainTextArray.slice(i, i + this.BLOCK_SIZE);
            
            // Pad the last block if necessary
            if (dataBlock.length < this.BLOCK_SIZE) {
                const paddingLength = this.BLOCK_SIZE - dataBlock.length;
                dataBlock.push(...Array(paddingLength).fill(paddingLength));
            }

            // Encrypt the block
            const encryptedBlock = this.encryptBlock(dataBlock, previousBlock);
            encryptedResult.push(...encryptedBlock);
            
            // Update previous block for next iteration
            previousBlock = encryptedBlock;
        }

        // Convert to Base64 for storage/transmission
        return btoa(String.fromCharCode(...encryptedResult));
    }

    /**
     * Decrypts the input text using CBC mode.
     */
    decrypt(cipherText) {
        // Decode Base64
        const decodedString = atob(cipherText);
        const cipherTextArray = Array.from(decodedString, char => char.charCodeAt(0));
        
        const decryptedResult = [];
        let previousBlock = this.iv; // Start with IV

        // Process each block
        for (let i = 0; i < cipherTextArray.length; i += this.BLOCK_SIZE) {
            const dataBlock = cipherTextArray.slice(i, i + this.BLOCK_SIZE);
            
            // Decrypt the block
            const decryptedBlock = this.decryptBlock(dataBlock, previousBlock);
            decryptedResult.push(...decryptedBlock);
            
            // Update previous block for next iteration
            previousBlock = dataBlock;
        }

        // Remove padding
        const paddingLength = decryptedResult[decryptedResult.length - 1];
        if (paddingLength <= this.BLOCK_SIZE) {
            decryptedResult.splice(-paddingLength);
        }

        // Convert to string
        return this.UTF8ArrToStr(decryptedResult).trim();
    }
} 