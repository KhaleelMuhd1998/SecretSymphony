import os
import json
import hashlib
import base64
import random

# Generate random key of given length
def generate_random_key(length):
    return ''.join(chr(random.randint(0, 255)) for _ in range(length))

# XOR operation between two strings
def xor_strings(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))

# Shift a character
def shift_character(char, shift_value, increment=True):
    char_code = ord(char)
    return chr((char_code + shift_value) % 256 if increment else (char_code - shift_value) % 256)

# Scramble the key using shift values (alternating + and -)
def shift_key_characters(key, shift_values):
    result = ''
    increment = True
    for i in range(len(key)):
        shift = shift_values[i % len(shift_values)]
        result += shift_character(key[i], shift, increment)
        increment = not increment
    return result

# Reverse scramble
def reverse_shift_key_characters(shifted_key, shift_values):
    result = ''
    increment = True
    for i in range(len(shifted_key)):
        shift = shift_values[i % len(shift_values)]
        result += shift_character(shifted_key[i], shift, not increment)
        increment = not increment
    return result

# Convert PIN to shift values
def get_user_shift_values(pin):
    return [int(c) for c in pin]

# Generate SHA256 hash of a buffer
def generate_sha256(buffer):
    return hashlib.sha256(buffer).hexdigest()

# Encrypt a file
def encrypt_file_ss(input_file_path, pin, output_dir="", custom_data=None):
    if not os.path.exists(input_file_path):
        return { "status": False, "error": "Error: Input file not found." }

    if not pin.isdigit() or not (4 <= len(pin) <= 8):
        return { "status": False, "error": "Error: PIN must be a numeric string between 4 and 8 digits." }

    if output_dir:
        try:
            os.makedirs(output_dir, exist_ok=True)
            if not os.access(output_dir, os.W_OK):
                raise Exception()
        except:
            return { "status": False, "error": "Error: Output directory is not writable or accessible." }

    shift_values = get_user_shift_values(pin)
    with open(input_file_path, 'rb') as f:
        buffer = f.read()

    base64_data = base64.b64encode(buffer).decode('utf-8')
    hash_value = generate_sha256(buffer)

    original_key = generate_random_key(len(base64_data))
    scrambled_key = shift_key_characters(original_key, shift_values)
    encrypted_base64 = xor_strings(base64_data, original_key)

    base_name = os.path.splitext(os.path.basename(input_file_path))[0]
    metadata_file = os.path.join(output_dir, f"{base_name}.sse0")
    encrypted_file = os.path.join(output_dir, f"{base_name}.sse1")
    key_file = os.path.join(output_dir, f"{base_name}.sse2")

    with open(encrypted_file, 'w', encoding='latin1') as f:
        f.write(encrypted_base64)
    with open(key_file, 'w', encoding='latin1') as f:
        f.write(scrambled_key)

    metadata = {
        "default": {
            "hash": hash_value,
            "format": os.path.splitext(input_file_path)[1][1:]
        },
        "custom": custom_data or {}
    }
    with open(metadata_file, 'w') as f:
        json.dump(metadata, f, indent=2)

    return {
        "status": True,
        "metadataFilePath": metadata_file,
        "encryptedFilePath": encrypted_file,
        "keyFilePath": key_file
    }

# Decrypt a file
def decrypt_file_ss(metadata_file_path, encrypted_file_path, key_file_path, pin, output_dir="", delete_encrypted_files=False):
    if output_dir:
        try:
            os.makedirs(output_dir, exist_ok=True)
            if not os.access(output_dir, os.W_OK):
                raise Exception()
        except:
            return { "status": False, "error": "Error: Output directory is not writable or accessible." }

    with open(metadata_file_path, 'r') as f:
        metadata = json.load(f)

    shift_values = get_user_shift_values(pin)
    expected_hash = metadata["default"]["hash"]

    with open(encrypted_file_path, 'r', encoding='latin1') as f:
        encrypted_base64 = f.read()
    with open(key_file_path, 'r', encoding='latin1') as f:
        scrambled_key = f.read()

    original_key = reverse_shift_key_characters(scrambled_key, shift_values)
    decrypted_base64 = xor_strings(encrypted_base64, original_key)
    decoded_buffer = base64.b64decode(decrypted_base64)

    actual_hash = generate_sha256(decoded_buffer)
    if actual_hash != expected_hash:
        return { "status": False, "error": "Error: Decryption failed due to hash mismatch." }

    base_name = os.path.splitext(os.path.basename(encrypted_file_path))[0]
    file_ext = metadata["default"].get("format", "ssdf")
    decrypted_file_path = os.path.join(output_dir, f"{base_name}_ss.{file_ext}")

    with open(decrypted_file_path, 'wb') as f:
        f.write(decoded_buffer)

    if delete_encrypted_files:
        try:
            os.remove(metadata_file_path)
            os.remove(encrypted_file_path)
            os.remove(key_file_path)
        except:
            print("Warning: Could not delete encrypted files.")

    return {
        "status": True,
        "decryptedFilePath": decrypted_file_path,
        "custom": metadata.get("custom", {})
    }
