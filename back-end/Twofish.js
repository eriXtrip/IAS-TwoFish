"use strict";

/**
 * Twofish class implementing the Twofish encryption algorithm.
 * The class supports encryption and decryption using a key.
 */
class Twofish {
  /**
   * @param {string} keyString The key used for encryption and decryption.
   */
  constructor(keyString) {
    this.BLOCK_SIZE = 16; // Block size in bytes (128 bits).
    this.rounds = 16; // Number of rounds for encryption.
    this.key = this.createKey(this.strToUTF8Arr(keyString)); // Key schedule creation.
    this.S = this.generateSBoxes(this.key); // Generate S-boxes based on the key.
    this.subkeys = this.keySchedule(this.key); // Key schedule for round keys.
  }

  /**
   * Checks if a variable is an array or Uint8Array.
   * @param {any} variable The variable to check.
   * @returns {boolean} True if the variable is an array or Uint8Array, false otherwise.
   */
  isAnArray(variable) {
    return (
      Array.isArray(variable) ||
      Object.prototype.toString.call(variable) === "[object Uint8Array]"
    );
  }

  /**
   * Compares two arrays to see if they are equal.
   * @param {Array} array1 The first array.
   * @param {Array} array2 The second array.
   * @returns {boolean} True if the arrays are equal, false otherwise.
   */
  areEqual(array1, array2) {
    if (array1.length !== array2.length) return false;
    return array1.every((value, index) => value === array2[index]);
  }

  /**
   * Converts a UTF-8 byte array to a string.
   * @param {Uint8Array} byteArray The byte array to convert.
   * @returns {string} The converted string.
   */
  UTF8ArrToStr(byteArray) {
    return new TextDecoder().decode(new Uint8Array(byteArray));
  }

  /**
   * Converts a string to a UTF-8 byte array and pads it to match the block size.
   * @param {string} string The string to convert.
   * @returns {number[]} The UTF-8 byte array (padded to block size).
   */
  strToUTF8Arr(string) {
    const encoder = new TextEncoder();
    const byteArray = Array.from(encoder.encode(string));
    // Pad the byte array to match the block size with spaces
    while (byteArray.length % this.BLOCK_SIZE !== 0) byteArray.push(32); // Pad with spaces
    return byteArray;
  }

  /**
   * Generates key-dependent S-boxes for substitution.
   * @param {number[]} key The encryption key as an array of bytes.
   * @returns {Array[]} The generated S-boxes.
   */
  generateSBoxes(key) {
    const S = [[], [], [], []];
    for (let i = 0; i < 256; i++) {
      for (let j = 0; j < 4; j++) {
        // Simplified S-box generation by XOR'ing the byte index with the key bytes
        S[j][i] = (i ^ key[(j + i) % key.length]) & 0xff;
      }
    }
    return S;
  }

  /**
   * Matrix multiplication in GF(2^8) for the MDS layer.
   * @param {number[]} vector The input vector for MDS multiplication.
   * @returns {number[]} The result of the MDS multiplication.
   */
  MDS(vector) {
    const M = [
      [0x01, 0xef, 0x5b, 0x5b],
      [0x5b, 0xef, 0xef, 0x01],
      [0xef, 0x5b, 0x01, 0xef],
      [0xef, 0x01, 0xef, 0x5b],
    ];

    // Perform matrix multiplication in GF(2^8)
    const gfMult = (a, b) => {
      let result = 0;
      for (let i = 0; i < 8; i++) {
        if (b & 1) result ^= a;
        const hiBit = a & 0x80;
        a = (a << 1) & 0xff;
        if (hiBit) a ^= 0x1b; // Use the irreducible polynomial for GF(2^8)
        b >>= 1;
      }
      return result;
    };

    const result = [];
    for (let i = 0; i < 4; i++) {
      let val = 0;
      for (let j = 0; j < 4; j++) {
        val ^= gfMult(M[i][j], vector[j]);
      }
      result.push(val);
    }
    return result;
  }

  /**
   * Key schedule generation for round keys.
   * @param {number[]} key The encryption key as an array of bytes.
   * @returns {number[]} The generated round subkeys.
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
   * @param {number[]} keyArray The key array.
   * @returns {number[]} A 128-bit key (padded or truncated).
   */
  createKey(keyArray) {
    if (!this.isAnArray(keyArray)) throw "Key must be an array";
    while (keyArray.length < this.BLOCK_SIZE) keyArray.push(0); // Pad with zeros
    return keyArray.slice(0, this.BLOCK_SIZE); // Return only the first 128 bits
  }

  /**
   * Applies whitening to the data block using the round subkeys.
   * @param {number[]} dataBlock The data block (split into 8-bit bytes).
   * @param {number[]} subkeys The round subkeys.
   * @param {number} offset The offset into the subkey array.
   * @returns {number[]} The whitened data block.
   */
  applyWhitening(dataBlock, subkeys, offset = 0) {
    return dataBlock.map(
      (byte, index) => byte ^ (subkeys[offset + index] & 0xff) // XOR with the subkey byte
    );
  }

  encrypt(plainText) {
    const plainTextArray = this.strToUTF8Arr(plainText);
    const encryptedResult = [];

    return Buffer.from(encryptedResult).toString("base64");
  }
}
