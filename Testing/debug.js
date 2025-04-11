const fs = require('fs');
const readline = require('readline');

/**
 * Generate a random key of the given length.
 */
function generateRandomKey(length) {
    let key = '';
    for (let i = 0; i < length; i++) {
        const randomChar = String.fromCharCode(Math.floor(Math.random() * 256));
        key += randomChar;
    }
    return key;
}

/**
 * XOR operation between two strings.
 */
function xorStrings(s1, s2) {
    let result = '';
    for (let i = 0; i < s1.length; i++) {
        const xorChar = String.fromCharCode(s1.charCodeAt(i) ^ s2.charCodeAt(i));
        result += xorChar;
    }
    return result;
}

/**
 * Encrypt Base64 using XOR with the key.
 */
function encryptBase64(base64String, key) {
    return xorStrings(base64String, key);
}

/**
 * Decrypt Base64 using XOR with the key.
 */
function decryptBase64(encryptedString, key) {
    return xorStrings(encryptedString, key);
}

/**
 * Shift character by value in specified direction.
 */
function shiftCharacter(char, shiftValue, increment) {
    const charCode = char.charCodeAt(0);
    const newCharCode = increment ? charCode + shiftValue : charCode - shiftValue;
    return String.fromCharCode(newCharCode);
}

/**
 * Shift key characters with alternating directions.
 */
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

/**
 * Reverse the shift applied to the key.
 */
function reverseShiftKeyCharacters(shiftedKey, shiftValues) {
    let originalKey = '';
    let increment = true;
    for (let i = 0; i < shiftedKey.length; i++) {
        const shiftValue = shiftValues[i % shiftValues.length];
        // Reverse the direction
        originalKey += shiftCharacter(shiftedKey[i], shiftValue, !increment);
        increment = !increment;
    }
    return originalKey;
}

/**
 * Convert user input to array of numeric shift values.
 */
function getUserShiftValues(input) {
    return input.split('').map(Number);
}

// ---------- Main Program ----------

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.question('Enter a numerical value (up to 8 digits): ', (input) => {
    if (!/^\d{1,8}$/.test(input)) {
        console.log('Invalid input. Please enter a numerical value with up to 8 digits.');
        rl.close();
        return;
    }

    const shiftValues = getUserShiftValues(input);

    const imageData = fs.readFileSync('image.png');
    const base64Image = Buffer.from(imageData).toString('base64');
    console.log("Original Base64 (first 60 characters):", base64Image.slice(0, 60));

    const originalKey = generateRandomKey(base64Image.length);
    const scrambledKey = shiftKeyCharacters(originalKey, shiftValues);
    console.log("Scrambled Key (first 60):", scrambledKey.slice(0, 60));

    const encryptedBase64 = encryptBase64(base64Image, originalKey);
    console.log("Encrypted Base64 (first 60 characters):", encryptedBase64.slice(0, 60));

    fs.writeFileSync('encrypted_base64.txt', encryptedBase64);
    fs.writeFileSync('encryption_key.txt', scrambledKey);

    const encryptedBase64FromFile = fs.readFileSync('encrypted_base64.txt', 'utf-8');
    const scrambledKeyFromFile = fs.readFileSync('encryption_key.txt', 'utf-8');

    const reconstructedKey = reverseShiftKeyCharacters(scrambledKeyFromFile, shiftValues);
    const decryptedBase64 = decryptBase64(encryptedBase64FromFile, reconstructedKey);
    console.log("Decrypted Base64 (first 60 characters):", decryptedBase64.slice(0, 60));

    const decodedImageData = Buffer.from(decryptedBase64, 'base64');
    fs.writeFileSync('decrypted_image.png', decodedImageData);

    rl.close();
});