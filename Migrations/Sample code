function generateKey(length) {
    let key = new Uint8Array(length);
    window.crypto.getRandomValues(key);
    return key;
}

function xorBytes(data, key) {
    return data.map((byte, index) => byte ^ key[index]);
}

// Encrypting the message
let message = "This is a secret message.";
let encoder = new TextEncoder();
let messageBytes = encoder.encode(message);
let key = generateKey(messageBytes.length);
let ciphertext = xorBytes(messageBytes, key);

console.log("Ciphertext:", ciphertext);

// Decrypting the message
let decryptedBytes = xorBytes(ciphertext, key);
let decoder = new TextDecoder();
let decryptedMessage = decoder.decode(decryptedBytes);

console.log("Decrypted Message:", decryptedMessage);

