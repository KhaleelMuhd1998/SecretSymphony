import os
import json
import base64
import hashlib
from pathlib import Path
from datetime import datetime

SECRETSYMPHONY_VERSION = "0.0.1"
SECRETSYMPHONY_PLATFORM = "Python"

EPOCH_OFFSET = 946684800  # Jan 1, 2000 UTC

# ------------------------------
# Utility Functions
# ------------------------------

def get_current_custom_time():
    now = int(datetime.utcnow().timestamp())
    return now - EPOCH_OFFSET

def convert_to_custom_time(timestamp):
    return int(timestamp // 1000) - EPOCH_OFFSET

def convert_from_custom_time(custom_time):
    return (custom_time + EPOCH_OFFSET) * 1000

def generate_random_key(length):
    return os.urandom(length)

def xor_bytes(data1, data2):
    return bytes(a ^ b for a, b in zip(data1, data2))

def shift_key_characters(key: bytes, shift_values):
    shifted = bytearray()
    increment = True
    for i, b in enumerate(key):
        shift = shift_values[i % len(shift_values)]
        shifted.append((b + shift) % 256 if increment else (b - shift) % 256)
        increment = not increment
    return bytes(shifted)

def reverse_shift_key_characters(shifted_key: bytes, shift_values):
    original = bytearray()
    increment = True
    for i, b in enumerate(shifted_key):
        shift = shift_values[i % len(shift_values)]
        original.append((b - shift) % 256 if increment else (b + shift) % 256)
        increment = not increment
    return bytes(original)

def get_user_shift_values(pin):
    return [int(d) for d in str(pin)]

def generate_sha256(data: bytes):
    return hashlib.sha256(data).hexdigest()

# ------------------------------
# Decryption Function
# ------------------------------

def decrypt_file_ss(metadata_file_path, encrypted_file_path, key_file_path, pin, output_dir=None, delete_encrypted_files=False):
    if not all(os.path.isfile(p) for p in [metadata_file_path, encrypted_file_path, key_file_path]):
        return {"status": False, "error": "One or more input files are missing."}

    if not pin.isdigit() or not (4 <= len(pin) <= 8):
        return {"status": False, "error": "PIN must be a numeric string between 4 and 8 digits."}

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    else:
        output_dir = os.path.dirname(encrypted_file_path)

    with open(metadata_file_path, 'r') as f:
        metadata = json.load(f)

    shift_values = get_user_shift_values(pin)
    expected_hash = metadata['default']['hash']

    with open(encrypted_file_path, 'rb') as f:
        encrypted_raw = f.read()

    flag = encrypted_raw[0]
    full_shift_values = shift_values[:]

    if flag == 1:
        masked = int.from_bytes(encrypted_raw[1:9], 'big')
        pin_hash = hashlib.sha256(pin.encode()).digest()[:8]
        mask = int.from_bytes(pin_hash, 'big')
        expiry = masked ^ mask
        now = get_current_custom_time()
        if now > expiry:
            return {"status": False, "error": "File has expired and cannot be decrypted."}

        expiry_digits = [int(d) for d in str(expiry)]
        full_shift_values += expiry_digits
        encrypted_base64 = encrypted_raw[9:]
    else:
        encrypted_base64 = encrypted_raw[1:]

    with open(key_file_path, 'rb') as f:
        scrambled_key = f.read()

    original_key = reverse_shift_key_characters(scrambled_key, full_shift_values)
    decrypted_base64 = xor_bytes(encrypted_base64, original_key)
    decoded_buffer = base64.b64decode(decrypted_base64)

    actual_hash = generate_sha256(decoded_buffer)
    if actual_hash != expected_hash:
        return {"status": False, "error": "Hash mismatch. Decryption failed."}

    base_name = Path(encrypted_file_path).stem
    file_format = metadata['default'].get('format', 'bin')
    output_file_path = Path(output_dir) / f"{base_name}_ss.{file_format}"

    with open(output_file_path, 'wb') as f:
        f.write(decoded_buffer)

    if delete_encrypted_files:
        for file_path in [metadata_file_path, encrypted_file_path, key_file_path]:
            try:
                os.remove(file_path)
            except Exception:
                pass

    return {
        "status": True,
        "decrypted_file_path": str(output_file_path),
        "custom": metadata.get("custom", {})
    }

# ------------------------------
# Encryption Function
# ------------------------------

def encrypt_file_ss(input_file_path, pin, output_dir=None, expiry_time=None, custom_data=None):
    if not os.path.isfile(input_file_path):
        return {"status": False, "error": "Input file not found."}

    if not pin.isdigit() or not (4 <= len(pin) <= 8):
        return {"status": False, "error": "PIN must be a numeric string between 4 and 8 digits."}

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    else:
        output_dir = os.path.dirname(input_file_path)

    shift_values = get_user_shift_values(pin)

    with open(input_file_path, 'rb') as f:
        buffer = f.read()

    base64_data = base64.b64encode(buffer)
    hash_digest = generate_sha256(buffer)

    original_key = generate_random_key(len(base64_data))

    # Append expiry shifts to shift values
    full_shift_values = shift_values[:]
    if expiry_time is not None:
        expiry_digits = [int(d) for d in str(convert_to_custom_time(expiry_time))]
        full_shift_values += expiry_digits

    scrambled_key = shift_key_characters(original_key, full_shift_values)
    encrypted_data = xor_bytes(base64_data, original_key)

    # Handle expiry masking and prepending
    if expiry_time is not None:
        expiry_seconds = convert_to_custom_time(expiry_time)
        pin_hash = hashlib.sha256(pin.encode()).digest()[:8]
        masked_expiry = expiry_seconds ^ int.from_bytes(pin_hash, 'big')
        expiry_buffer = bytearray([1]) + masked_expiry.to_bytes(8, 'big')
    else:
        expiry_buffer = bytearray([0])

    final_encrypted = bytes(expiry_buffer) + encrypted_data

    base_name = Path(input_file_path).stem
    metadata_path = Path(output_dir) / f"{base_name}.sse0"
    encrypted_path = Path(output_dir) / f"{base_name}.sse1"
    key_path = Path(output_dir) / f"{base_name}.sse2"

    metadata = {
        "secretsymphony": {
            "version": SECRETSYMPHONY_VERSION,
            "platform": SECRETSYMPHONY_PLATFORM
        },
        "default": {
            "hash": hash_digest,
            "format": Path(input_file_path).suffix.lstrip('.')
        },
        "custom": custom_data or {}
    }

    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)

    with open(encrypted_path, 'wb') as f:
        f.write(final_encrypted)

    with open(key_path, 'wb') as f:
        f.write(scrambled_key)

    return {
        "status": True,
        "metadata_file_path": str(metadata_path),
        "encrypted_file_path": str(encrypted_path),
        "key_file_path": str(key_path)
    }
