const SecretSymphonyVersion = "1.0.0";
const SecretSymphonyPlatform = "TypeScript";

function getCurrentCustomTime(): bigint {
  return BigInt(Math.floor(Date.now() / 1000) - 946684800);
}

function convertToCustomTime(timestamp: number): bigint {
  return BigInt(Math.floor(timestamp / 1000) - 946684800);
}

function generateRandomKey(length: number): Uint8Array {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return array;
}

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

function shiftKeyCharacters(key: Uint8Array, shiftValues: number[]): Uint8Array {
  const shifted = new Uint8Array(key.length);
  let increment = true;
  for (let i = 0; i < key.length; i++) {
    const shift = shiftValues[i % shiftValues.length];
    shifted[i] = increment
      ? (key[i] + shift) % 256
      : (key[i] - shift + 256) % 256;
    increment = !increment;
  }
  return shifted;
}

function reverseShiftKeyCharacters(key: Uint8Array, shiftValues: number[]): Uint8Array {
  const original = new Uint8Array(key.length);
  let increment = true;
  for (let i = 0; i < key.length; i++) {
    const shift = shiftValues[i % shiftValues.length];
    original[i] = increment
      ? (key[i] - shift + 256) % 256
      : (key[i] + shift) % 256;
    increment = !increment;
  }
  return original;
}

function getUserShiftValues(pin: string): number[] {
  return Array.from(pin).map((c) => parseInt(c, 10));
}

async function generateSHA256Async(data: Uint8Array): Promise<string> {
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function encryptFileSS(
  inputFile: File,
  pin: string,
  expiryTime: number | null,
  customData: Record<string, any>
): Promise<{ metadata: object; encryptedFile: Blob; keyFile: Blob }> {
  const buffer = new Uint8Array(await inputFile.arrayBuffer());
  const base64Data = new TextEncoder().encode(btoa(String.fromCharCode(...buffer)));

  const hash = await generateSHA256Async(buffer);
  const shiftValues = getUserShiftValues(pin);
  let fullShiftValues = [...shiftValues];

  if (expiryTime !== null) {
    const expiryDigits = Array.from(convertToCustomTime(expiryTime).toString()).map(Number);
    fullShiftValues = fullShiftValues.concat(expiryDigits);
  }

  const key = generateRandomKey(base64Data.length);
  const scrambledKey = shiftKeyCharacters(key, fullShiftValues);
  const encryptedData = xorBytes(base64Data, key);

  const expiryFlag = expiryTime !== null ? 1 : 0;
  const expiryBuffer = expiryFlag === 1
    ? (async () => {
        const expiry = convertToCustomTime(expiryTime!);
        const pinHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pin)));
        const mask = pinHash.slice(0, 8);
        let masked = expiry ^ BigInt("0x" + [...mask].map(b => b.toString(16).padStart(2, '0')).join(''));
        const maskedBytes = new Uint8Array(8);
        for (let i = 7; i >= 0; i--) {
          maskedBytes[i] = Number(masked & 0xffn);
          masked >>= 8n;
        }
        return new Uint8Array([1, ...maskedBytes]);
      })()
    : new Uint8Array([0]);

  const finalEncrypted = new Blob([expiryBuffer, encryptedData]);

  const metadata = {
    secretsymphony: {
      version: SecretSymphonyVersion,
      platform: SecretSymphonyPlatform
    },
    default: {
      hash,
      format: inputFile.name.split('.').pop()
    },
    custom: customData || {}
  };

  return {
    metadata,
    encryptedFile: finalEncrypted,
    keyFile: new Blob([scrambledKey])
  };
}

export async function decryptFileSS(
  encryptedFile: Blob,
  keyFile: Blob,
  metadata: any,
  pin: string
): Promise<{ decryptedFile: Blob; custom: Record<string, any> }> {
  const encryptedBuffer = new Uint8Array(await encryptedFile.arrayBuffer());
  const keyBuffer = new Uint8Array(await keyFile.arrayBuffer());

  const shiftValues = getUserShiftValues(pin);
  let fullShiftValues = [...shiftValues];

  let encryptedBase64: Uint8Array;
  const flag = encryptedBuffer[0];

  if (flag === 1) {
    const masked = encryptedBuffer.slice(1, 9);
    const pinHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pin)));
    const mask = pinHash.slice(0, 8);

    const maskedBigInt = [...masked].reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
    const maskBigInt = [...mask].reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
    const expiry = maskedBigInt ^ maskBigInt;

    if (getCurrentCustomTime() > expiry) {
      throw new Error("File has expired.");
    }

    const expiryDigits = Array.from(expiry.toString()).map(Number);
    fullShiftValues = fullShiftValues.concat(expiryDigits);
    encryptedBase64 = encryptedBuffer.slice(9);
  } else {
    encryptedBase64 = encryptedBuffer.slice(1);
  }

  const originalKey = reverseShiftKeyCharacters(keyBuffer, fullShiftValues);
  const decryptedBase64 = xorBytes(encryptedBase64, originalKey);
  const decryptedBinary = new Uint8Array(atob(new TextDecoder().decode(decryptedBase64)).split('').map(c => c.charCodeAt(0)));

  const actualHash = await generateSHA256Async(decryptedBinary);
  const expectedHash = metadata.default.hash;
  if (actualHash !== expectedHash) {
    throw new Error("Decryption failed: hash mismatch.");
  }

  return {
    decryptedFile: new Blob([decryptedBinary]),
    custom: metadata.custom || {}
  };
}
