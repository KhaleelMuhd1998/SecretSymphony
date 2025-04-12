const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Generate a random key string of given length with random ASCII characters
function generateRandomKey(length) {
    let key = '';
    for (let i = 0; i < length; i++) {
        const randomChar = String.fromCharCode(Math.floor(Math.random() * 256));
        key += randomChar;
    }
    return key;
}

// Perform XOR operation between each character of two strings
function xorStrings(s1, s2) {
    let result = '';
    for (let i = 0; i < s1.length; i++) {
        const xorChar = String.fromCharCode(s1.charCodeAt(i) ^ s2.charCodeAt(i));
        result += xorChar;
    }
    return result;
}

// Shift a single character by the given value, forward or backward
function shiftCharacter(char, shiftValue, increment) {
    const charCode = char.charCodeAt(0);
    const newCharCode = increment ? charCode + shiftValue : charCode - shiftValue;
    return String.fromCharCode(newCharCode);
}

// Apply alternating character shifts (+/-) across the key using shift values
function shiftKeyCharacters(key, shiftValues) {
    let shiftedKey = '';
    let increment = true;
    for (let i = 0; i < key.length; i++) {
        const shiftValue = shiftValues[i % shiftValues.length];
        shiftedKey += shiftCharacter(key[i], shiftValue, increment);
        increment = !increment;
    }
    return shiftedKey;
}

// Reverse the alternating character shifts to recover the original key
function reverseShiftKeyCharacters(shiftedKey, shiftValues) {
    let originalKey = '';
    let increment = true;
    for (let i = 0; i < shiftedKey.length; i++) {
        const shiftValue = shiftValues[i % shiftValues.length];
        originalKey += shiftCharacter(shiftedKey[i], shiftValue, !increment);
        increment = !increment;
    }
    return originalKey;
}

// Convert a numeric PIN string to an array of single-digit shift values
function getUserShiftValues(input) {
    return input.split('').map(Number);
}

// Generate SHA-256 hash of a file buffer
function generateSHA256(buffer) {
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

// Encrypt a file using XOR with a scrambled key derived from a numeric PIN
/**
 * @typedef {Object} EncryptFileObjectSS
 * @property {string} inputFilePath - Path to the file to encrypt
 * @property {string} pin - PIN used for encryption
 * @property {string} [outputDir] - Output directory path (optional)
 *
 * @typedef {Object} EncryptFileResultSS
 * @property {boolean} status - Operation status
 * @property {string} metadataFilePath - Path to the generated .sse0 file
 * @property {string} encryptedFilePath - Path to the generated .sse1 file
 * @property {string} keyFilePath - Path to the generated .sse2 file
 * @property {string} [error] - Error message (if failed)
*/
function encryptFileSS({ inputFilePath, pin = "", embedPin = false, outputDir = "" }) {
    if (!fs.existsSync(inputFilePath)) {
        return {
            status: false,
            error: 'Error: Input file not found.'
        };
    }

    if (!/^[0-9]{4,8}$/.test(pin)) {
        return {
            status: false,
            error: 'Error: PIN must be a numeric string between 4 and 8 digits.'
        };
    }

    if (outputDir && !fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }

    const shiftValues = getUserShiftValues(pin);
    const buffer = fs.readFileSync(inputFilePath);
    const base64Data = Buffer.from(buffer).toString('base64');
    const hash = generateSHA256(buffer);

    const originalKey = generateRandomKey(base64Data.length);
    const scrambledKey = shiftKeyCharacters(originalKey, shiftValues);
    const encryptedBase64 = xorStrings(base64Data, originalKey);

    const baseName = path.basename(inputFilePath, path.extname(inputFilePath));
    const metadataFilePath = path.join(outputDir, `${baseName}.sse0`);
    const encryptedFilePath = path.join(outputDir, `${baseName}.sse1`);
    const keyFilePath = path.join(outputDir, `${baseName}.sse2`);

    fs.writeFileSync(encryptedFilePath, encryptedBase64);
    fs.writeFileSync(keyFilePath, scrambledKey);

    const metadata = {
        default: {
            hash,
            format: path.extname(inputFilePath).substring(1),
            ...(embedPin && { pin })
        },
        custom: {}
    };
    fs.writeFileSync(metadataFilePath, JSON.stringify(metadata, null, 2));

    return {
        status: true,
        metadataFilePath,
        encryptedFilePath,
        keyFilePath
    };
}

// Decrypt a file using XOR and the metadata-provided or user-provided PIN
/**
 * @typedef {Object} DecryptFileObjectSS
 * @property {string} metadataFilePath - Path to the .sse0 metadata file
 * @property {string} encryptedFilePath - Path to the .sse1 encrypted file
 * @property {string} keyFilePath - Path to the .sse2 scrambled key
 * @property {string} pin - PIN used to reverse key scrambling
 * @property {string} [outputDir] - Output directory path (optional)
 *
 * @typedef {Object} DecryptFileResultSS
 * @property {boolean} status - Operation status
 * @property {string} [decryptedFilePath] - Path to the restored .png file (if successful)
 * @property {string} [error] - Error message (if failed)
 */
function decryptFileSS({ metadataFilePath, encryptedFilePath, keyFilePath, pin, outputDir = "" }) {
    const metadata = JSON.parse(fs.readFileSync(metadataFilePath, 'utf-8'));
    const embeddedPin = metadata.default.pin;
    const effectivePin = embeddedPin || pin;
    const shiftValues = getUserShiftValues(effectivePin);
    const expectedHash = metadata.default.hash;

    const encryptedBase64 = fs.readFileSync(encryptedFilePath, 'utf-8');
    const scrambledKey = fs.readFileSync(keyFilePath, 'utf-8');

    const originalKey = reverseShiftKeyCharacters(scrambledKey, shiftValues);
    const decryptedBase64 = xorStrings(encryptedBase64, originalKey);
    const decodedBuffer = Buffer.from(decryptedBase64, 'base64');

    const actualHash = generateSHA256(decodedBuffer);
    if (actualHash !== expectedHash) {
        return {
            status: false,
            error: 'Error: Decryption failed due to hash mismatch.'
        };
    }

    const baseName = path.basename(encryptedFilePath, '.sse1');
    const format = metadata.default.format || 'ssdf';
    const decryptedFilePath = path.join(outputDir, `${baseName}_ss.${format}`);
    fs.writeFileSync(decryptedFilePath, decodedBuffer);

    return {
        status: true,
        decryptedFilePath
    };
}

module.exports = {
    encryptFileSS,
    decryptFileSS
};
