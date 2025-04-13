const path = require('path');
const { encryptFileSS, decryptFileSS } = require('../JavaScript/CommonJS/SecretSymphony');

const inputFilePath = 'image.png';  // Replace with actual test image path
const pin = '12345678';
const outputDir = path.resolve(__dirname, 'EncryptedFiles');

// Set expiration to 1 minute from now
const expiryTime = Date.now() + 60 * 1000;
// const expiryTime = null;

// Encrypt
const encryptionResult = encryptFileSS({
    inputFilePath,
    pin,
    outputDir,
    expiryTime,
    customData: {
        Name: 'Secret Symphony'
    }
});

if (!encryptionResult.status) {
    console.error('Encryption failed:', encryptionResult.error);
    process.exit(1);
}

console.log('Encryption successful!');
console.log('Metadata File:', encryptionResult.metadataFilePath);
console.log('Encrypted File:', encryptionResult.encryptedFilePath);
console.log('Key File:', encryptionResult.keyFilePath);

// Decrypt
const decryptionResult = decryptFileSS({
    metadataFilePath: "./EncryptedFiles/image.sse0",
    encryptedFilePath: "./EncryptedFiles/image.sse1",
    keyFilePath: "./EncryptedFiles/image.sse2",
    pin,
    outputDir: "./DecryptedFiles/",
    deleteEncryptedFiles: false
});

if (!decryptionResult.status) {
    console.error('Decryption failed:', decryptionResult.error);
    process.exit(1);
}

console.log('Decryption successful!');
console.log('Decrypted File:', decryptionResult.decryptedFilePath);
console.log('Custom Metadata:', decryptionResult.custom);
