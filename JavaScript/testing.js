function caesarCipher(text, shift) {
    return text.split('').map(char => {
        if (char.match(/[a-z]/i)) {
            let charCode = char.charCodeAt(0);
            let base = char >= 'a' ? 97 : 65;
            return String.fromCharCode(((charCode - base + shift) % 26) + base);
        }
        return char; // Non-alphabetic characters remain unchanged
    }).join('');
}

// Example usage:
let plaintext = "Hello, World!";
let shift = 3;

let encrypted = caesarCipher(plaintext, shift);
console.log("Encrypted:", encrypted);

let decrypted = caesarCipher(encrypted, 26 - shift); // Decrypt by reversing the shift
console.log("Decrypted:", decrypted);