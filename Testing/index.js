const fs = require('fs');
const readline = require('readline');

/**
 * Function to generate a random key of a given length
 * @param {number} length - The length of the key to be generated
 * @returns {string} - The generated random key
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
 * Function to perform XOR operation between two strings
 * @param {string} s1 - The first string
 * @param {string} s2 - The second string (key)
 * @returns {string} - The resulting string after XOR operation
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
 * Function to encrypt a Base64 string using a key
 * @param {string} base64String - The Base64 encoded string
 * @param {string} key - The key to be used for encryption
 * @returns {string} - The encrypted Base64 string
 */
function encryptBase64(base64String, key) {
    return xorStrings(base64String, key);
}

/**
 * Function to decrypt an encrypted Base64 string using a key
 * @param {string} encryptedString - The encrypted Base64 string
 * @param {string} key - The key to be used for decryption
 * @returns {string} - The decrypted Base64 string
 */
function decryptBase64(encryptedString, key) {
    return xorStrings(encryptedString, key);
}

/**
 * Function to shift a character by a given shift value
 * @param {string} char - The character to be shifted
 * @param {number} shiftValue - The shift value
 * @returns {string} - The shifted character
 */
function shiftCharacter(char, shiftValue) {
    const charCode = char.charCodeAt(0);
    const newCharCode = charCode + shiftValue;
    return String.fromCharCode(newCharCode);
}

/**
 * Function to shift characters in the key based on an array of shift values
 * @param {string} key - The key to be shifted
 * @param {number[]} shiftValues - The array of shift values
 * @returns {string} - The shifted key
 */
function shiftKeyCharacters(key, shiftValues) {
    let shiftedKey = '';
    for (let i = 0; i < key.length; i++) {
        const shiftValue = shiftValues[i % shiftValues.length];
        shiftedKey += shiftCharacter(key[i], shiftValue);
    }
    return shiftedKey;
}

/**
 * Function to convert user input string to an array of numeric shift values
 * @param {string} input - The user input string containing numeric values
 * @returns {number[]} - The array of numeric shift values
 */
function getUserShiftValues(input) {
    return input.split('').map(Number);
}

// ----------------

// Create an interface for reading user input
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

// Prompt the user for a numerical value and process the input
rl.question('Enter a numerical value (up to 8 digits): ', (input) => {
    if (!/^\d{1,8}$/.test(input)) {
        console.log('Invalid input. Please enter a numerical value with up to 8 digits.');
        rl.close();
        return;
    }

    // Get shift values from user input
    const shiftValues = getUserShiftValues(input);

    // Read image and convert to Base64
    const imageData = fs.readFileSync('image.png');
    const base64Image = Buffer.from(imageData).toString('base64');

    // Print the beginning of the Base64 string for brevity
    console.log("Original Base64 (first 60 characters):", base64Image.slice(0, 60));

    // Generate a random key of the same length as the Base64 string
    const key = generateRandomKey(base64Image.length);

    // Shift the key characters based on user input
    const shiftedKey = shiftKeyCharacters(key, shiftValues);

    // Print the original and shifted keys
    console.log("Original Key:", key);
    console.log("Shifted Key:", shiftedKey);

    // Encrypt the Base64 string using the shifted key
    const encryptedBase64 = encryptBase64(base64Image, shiftedKey);

    // Print the beginning of the encrypted Base64 string for brevity
    console.log("Encrypted Base64 (first 60 characters):", encryptedBase64.slice(0, 60));

    // Write the encrypted Base64 string and the original key to files
    fs.writeFileSync('encrypted_base64.txt', encryptedBase64);
    fs.writeFileSync('encryption_key.txt', key);

    // Read the encrypted Base64 string and the original key from the files
    const encryptedBase64FromFile = fs.readFileSync('encrypted_base64.txt', 'utf-8');
    const keyFromFile = fs.readFileSync('encryption_key.txt', 'utf-8');

    // Shift the key characters from file based on user input
    const shiftedKeyFromFile = shiftKeyCharacters(keyFromFile, shiftValues);

    // Decrypt the encrypted Base64 string using the shifted key
    const decryptedBase64 = decryptBase64(encryptedBase64FromFile, shiftedKeyFromFile);

    // Print the beginning of the decrypted Base64 string for brevity
    console.log("Decrypted Base64 (first 60 characters):", decryptedBase64.slice(0, 60));

    // Decode the Base64 string back to image data
    const decodedImageData = Buffer.from(decryptedBase64, 'base64');

    // Write the decoded image data back to a file
    fs.writeFileSync('decrypted_image.png', decodedImageData);

    // Close the readline interface
    rl.close();
});
