/**
 * Project Name: Secret Symphony
 * Description: Security library for encrypting/decrypting Base64 data.
 * Version: 1.0.0
 * Contributors:
 * - Khaleel M <https://www.github.com/KhaleelMuhd1998>
 * - Surmai Adhikari <https://www.github.com/SAAS-s>
 * License: MIT
 * Repository: https://github.com/KhaleelMuhd1998/SecretSymphony
 */

// Libraries
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

// Details of Secret Symphony. Will be added to metadata file.
const secretsymphonyversion = '1.0.0';
const secretsymphonyplatform = 'JavaScript';

// Returns the current time in seconds since Jan 1, 2000
function getCurrentCustomTime() {
    const EPOCH_OFFSET = 946684800n;
    const currentSeconds = BigInt(Math.floor(Date.now() / 1000));
    return {
        seconds: currentSeconds - EPOCH_OFFSET
    };
}

// Converts standard JS timestamp to Custom Time (seconds since Jan 1, 2000)
function convertToCustomTime(timestamp) {
    const EPOCH_OFFSET = 946684800n;
    const seconds = BigInt(Math.floor(timestamp / 1000));
    return seconds - EPOCH_OFFSET;
}

// Converts Custom Time back to standard JS timestamp (in seconds)
function convertFromCustomTime(seconds) {
    const EPOCH_OFFSET = 946684800n;
    return seconds + EPOCH_OFFSET;
}

// Generates a random ASCII string (key) of given length
function generateRandomKey(length) {
    let key = '';
    for (let i = 0; i < length; i++) {
        const randomChar = String.fromCharCode(Math.floor(Math.random() * 256));
        key += randomChar;
    }
    return key;
}

// Performs XOR between two strings of equal length
function xorStrings(s1, s2) {
    let result = '';
    for (let i = 0; i < s1.length; i++) {
        const xorChar = String.fromCharCode(s1.charCodeAt(i) ^ s2.charCodeAt(i));
        result += xorChar;
    }
    return result;
}

// Shifts character forward or backward by a value
function shiftCharacter(char, shiftValue, increment) {
    const charCode = char.charCodeAt(0);
    const newCharCode = increment ? charCode + shiftValue : charCode - shiftValue;
    return String.fromCharCode(newCharCode);
}

// Applies alternating shifts to a key string based on a shift value array
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

// Reverses the key shifting process to get original key back
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

// Converts user PIN into numeric shift values array
function getUserShiftValues(input) {
    return input.split('').map(Number);
}

// Generates SHA-256 hash from a buffer
function generateSHA256(buffer) {
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

/**
 * Encrypts a file with PIN and optional expiry timestamp.
 *
 * @typedef {Object} EncryptFileObjectSS
 * @property {string} inputFilePath - Path to the file to encrypt
 * @property {string} pin - PIN used for encryption
 * @property {string} [outputDir] - Output directory path (optional)
 * @property {Object} [customData] - Optional custom metadata fields (developer-defined)
 *
 * @typedef {Object} EncryptFileResultSS
 * @property {boolean} status - Operation status
 * @property {string} metadataFilePath - Path to the generated .sse0 file
 * @property {string} encryptedFilePath - Path to the generated .sse1 file
 * @property {string} keyFilePath - Path to the generated .sse2 file
 * @property {string} [error] - Error message (if failed)
*/
function encryptFileSS({ inputFilePath, pin, outputDir = "", expiryTime = null, customData = {} }) {
    // Check if input file exists
    if (!fs.existsSync(inputFilePath)) {
        return { status: false, error: 'Error: Input file not found.' };
    }

    // Validate PIN format (must be 4 to 8 digits)
    if (!/^[0-9]{4,8}$/.test(pin)) {
        return { status: false, error: 'Error: PIN must be a numeric string between 4 and 8 digits.' };
    }

    // Ensure output directory exists and is writable
    try {
        if (outputDir && !fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }
        fs.accessSync(outputDir, fs.constants.W_OK);
    } catch (err) {
        return { status: false, error: 'Error: Output directory is not writable or accessible.' };
    }

    // Get shift values from PIN
    const shiftValues = getUserShiftValues(pin);

    // Read and encode file content
    const buffer = fs.readFileSync(inputFilePath);
    const base64Data = Buffer.from(buffer).toString('base64');
    const hash = generateSHA256(buffer);

    // Generate encryption key and scramble using shift values (and expiry if present)
    const originalKey = generateRandomKey(base64Data.length);
    let fullShiftValues = shiftValues;
    if (expiryTime) {
        const expiryDigits = [...(convertToCustomTime(expiryTime).toString())].map(Number);
        fullShiftValues = shiftValues.concat(expiryDigits);
    }

    // Scramble key and encrypt data
    const scrambledKey = shiftKeyCharacters(originalKey, fullShiftValues);
    const encryptedBase64 = xorStrings(base64Data, originalKey);

    // Create buffer from encrypted content
    let encryptedBuffer = Buffer.from(encryptedBase64);

    // Prepend flag and masked expiry if expiry is set
    if (expiryTime) {
        const expiry = convertToCustomTime(expiryTime);
        const hash = crypto.createHash('sha256').update(pin).digest();
        const mask = hash.subarray(0, 8);
        const maskedExpiry = expiry ^ BigInt('0x' + mask.toString('hex'));
        const expiryBuffer = Buffer.alloc(9); // 1 byte flag + 8 bytes expiry
        expiryBuffer.writeUInt8(1, 0); // Flag: 1 means expiry present
        expiryBuffer.writeBigUInt64BE(maskedExpiry, 1);
        encryptedBuffer = Buffer.concat([expiryBuffer, encryptedBuffer]);
    } else {
        const flagBuffer = Buffer.alloc(1);
        flagBuffer.writeUInt8(0, 0); // Flag: 0 means no expiry
        encryptedBuffer = Buffer.concat([flagBuffer, encryptedBuffer]);
    }

    const baseName = path.basename(inputFilePath, path.extname(inputFilePath));
    const metadataFilePath = path.join(outputDir, `${baseName}.sse0`);
    const encryptedFilePath = path.join(outputDir, `${baseName}.sse1`);
    const keyFilePath = path.join(outputDir, `${baseName}.sse2`);

    // Write all three output files
    fs.writeFileSync(encryptedFilePath, encryptedBuffer);
    fs.writeFileSync(keyFilePath, scrambledKey);

    // Write metadata file including format and hash
    const metadata = {
        secretsymphony: {
          version: secretsymphonyversion,
          platform: secretsymphonyplatform
        },
        default: {
            hash,
            format: path.extname(inputFilePath).substring(1)
        },
        custom: customData
    };
    fs.writeFileSync(metadataFilePath, JSON.stringify(metadata, null, 2));

    // Return output file paths
    return {
        status: true,
        metadataFilePath,
        encryptedFilePath,
        keyFilePath
    };
}

/**
 * Decrypts an encrypted file using metadata, PIN, and key
 * 
 * @typedef {Object} DecryptFileObjectSS
 * @property {string} metadataFilePath - Path to the .sse0 metadata file
 * @property {string} encryptedFilePath - Path to the .sse1 encrypted file
 * @property {string} keyFilePath - Path to the .sse2 scrambled key
 * @property {string} pin - PIN used to reverse key scrambling
 * @property {string} [outputDir] - Output directory path (optional)
 * @property {boolean} [deleteEncryptedFiles] - If true, deletes .sse0, .sse1, and .sse2 after successful decryption
 *
 * @typedef {Object} DecryptFileResultSS
 * @property {boolean} status - Operation status
 * @property {string} [decryptedFilePath] - Path to the restored output file (if successful)
 * @property {Object} [custom] - Custom metadata fields from the encrypted file (if any)
 * @property {string} [error] - Error message (if failed)
 */
function decryptFileSS({ metadataFilePath, encryptedFilePath, keyFilePath, pin, outputDir = "", deleteEncryptedFiles = false }) {
    // Ensure output directory exists
    try {
        if (outputDir && !fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }
        fs.accessSync(outputDir, fs.constants.W_OK);
    } catch (err) {
        return { status: false, error: 'Error: Output directory is not writable or accessible.' };
    }

    // Read metadata and extract expected hash
    const metadata = JSON.parse(fs.readFileSync(metadataFilePath, 'utf-8'));
    const shiftValues = getUserShiftValues(pin);
    const expectedHash = metadata.default.hash;

    // Read encrypted file
    const encryptedRaw = fs.readFileSync(encryptedFilePath);
    let encryptedBase64;
    let fullShiftValues = shiftValues;

    // Read the 1-byte flag to check if expiry is present
    const flag = encryptedRaw.readUInt8(0);
    if (flag === 1) {
        const masked = encryptedRaw.readBigUInt64BE(1);
        const hash = crypto.createHash('sha256').update(pin).digest();
        const mask = hash.subarray(0, 8);
        const expiry = masked ^ BigInt('0x' + mask.toString('hex'));
        const now = getCurrentCustomTime().seconds;
        if (now > expiry) {
            return { status: false, error: 'Error: This file has expired and cannot be decrypted.' };
        }
        const expiryDigits = [...(expiry.toString())].map(Number);
        fullShiftValues = shiftValues.concat(expiryDigits);
        encryptedBase64 = encryptedRaw.slice(9).toString();
    } else {
        encryptedBase64 = encryptedRaw.slice(1).toString();
    }

    // Read scrambled key and reverse it to get original
    const scrambledKey = fs.readFileSync(keyFilePath, 'utf-8');
    const originalKey = reverseShiftKeyCharacters(scrambledKey, fullShiftValues);

    // Decrypt base64 and convert back to buffer
    const decryptedBase64 = xorStrings(encryptedBase64, originalKey);
    const decodedBuffer = Buffer.from(decryptedBase64, 'base64');

    // Validate hash integrity
    const actualHash = generateSHA256(decodedBuffer);
    if (actualHash !== expectedHash) {
        return { status: false, error: 'Error: Decryption failed due to hash mismatch.' };
    }

    // Construct decrypted file path and write it
    const baseName = path.basename(encryptedFilePath, '.sse1');
    const format = metadata.default.format || 'ssdf';
    const decryptedFilePath = path.join(outputDir, `${baseName}_ss.${format}`);
    fs.writeFileSync(decryptedFilePath, decodedBuffer);

    // Optionally delete encrypted source files
    if (deleteEncryptedFiles) {
        try {
            fs.unlinkSync(metadataFilePath);
            fs.unlinkSync(encryptedFilePath);
            fs.unlinkSync(keyFilePath);
        } catch (err) {
            console.error('Error: Unable to delete encrypted files.');
        }
    }

    // Return final output path and custom metadata
    return {
        status: true,
        decryptedFilePath,
        custom: metadata.custom
    };
}

export {
    encryptFileSS,
    decryptFileSS
};
