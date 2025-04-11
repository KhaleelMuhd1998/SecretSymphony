import base64
import os
import random

# Function to generate a random key of a given length
def generate_random_key(length):
    return ''.join(chr(random.randint(0, 255)) for _ in range(length))

# XOR operation between two strings
def xor_strings(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))

# Shift a character by a given shift value
def shift_character(char, shift_value):
    return chr((ord(char) + shift_value) % 256)

# Shift characters in the key based on shift values
def shift_key_characters(key, shift_values):
    shifted = ''
    for i in range(len(key)):
        shift = shift_values[i % len(shift_values)]
        shifted += shift_character(key[i], shift)
    return shifted

# Convert user string to numeric shift values
def get_user_shift_values(input_str):
    return [int(ch) for ch in input_str]

# Main execution
def main():
    input_value = input("Enter a numerical value (up to 8 digits): ")
    if not input_value.isdigit() or len(input_value) > 8:
        print("Invalid input. Please enter a numerical value with up to 8 digits.")
        return

    shift_values = get_user_shift_values(input_value)

    # Read image and encode as base64
    with open('image.png', 'rb') as img_file:
        image_data = img_file.read()
    base64_image = base64.b64encode(image_data).decode('utf-8')
    print("Original Base64 (first 60 characters):", base64_image[:60])

    # Generate and shift key
    key = generate_random_key(len(base64_image))
    shifted_key = shift_key_characters(key, shift_values)
    print("Original Key (first 60):", key[:60])
    print("Shifted Key (first 60):", shifted_key[:60])

    # Encrypt
    encrypted_base64 = xor_strings(base64_image, shifted_key)
    print("Encrypted Base64 (first 60):", encrypted_base64[:60])

    # Save encrypted and key
    with open('encrypted_base64.txt', 'w', encoding='latin1') as f:
        f.write(encrypted_base64)
    with open('encryption_key.txt', 'w', encoding='latin1') as f:
        f.write(key)

    # Load from file
    with open('encrypted_base64.txt', 'r', encoding='latin1') as f:
        encrypted_from_file = f.read()
    with open('encryption_key.txt', 'r', encoding='latin1') as f:
        key_from_file = f.read()

    shifted_key_from_file = shift_key_characters(key_from_file, shift_values)
    decrypted_base64 = xor_strings(encrypted_from_file, shifted_key_from_file)
    print("Decrypted Base64 (first 60 characters):", decrypted_base64[:60])

    # Convert Base64 back to image
    decoded_image = base64.b64decode(decrypted_base64)
    with open('decrypted_image.png', 'wb') as f:
        f.write(decoded_image)

if __name__ == "__main__":
    main()
