use rand::Rng;          // Import random number generator
use std::str;

/// Generates a random key of the same length as the message.
/// Think of this as creating a "one-time use password" for encryption.
fn generate_key(length: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();          // Initialize a random number generator
    (0..length).map(|_| rng.gen::<u8>()).collect()          //  Generate random bytes equal to the message length
}

/// Applies XOR encryption/decryption on a given byte array using a key.
/// XOR is like flipping light switches: if you flip twice, youre back to the original.
fn xor_bytes(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().zip(key.iter())          // Pair each byte of data with its corresponding key byte
        .map(|(&d, &k)| d ^ k)              // Apply XOR operation on each byte pair
        .collect()                    // Collect the XORd bytes into a vector
}

fn main() {
    // Step 1: Convert the message to bytes
    let message = "This is a secret message.";  // The original text message
    let message_bytes = message.as_bytes();  // Convert it into a series of bytes
    
    // Step 2: Generate a random key of the same length as the message
    let key = generate_key(message_bytes.len());
