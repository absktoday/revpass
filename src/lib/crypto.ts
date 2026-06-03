// Cryptographic utilities for Passkey PRF-Protected Vault

export function arrayBufferToBase64(buffer: ArrayBufferLike): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function arrayBufferToBase64Url(buffer: ArrayBufferLike): string {
  return arrayBufferToBase64(buffer)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export function base64UrlToArrayBuffer(base64url: string): ArrayBuffer {
  let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  return base64ToArrayBuffer(base64);
}

// Generate the Master Encryption Key (MEK) - 256 bits
export function generateMEK(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

// Import the raw MEK bytes into a CryptoKey for AES-GCM
export async function importMEK(mekBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    mekBytes as any,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

// Derive the Passkey Derived Key (PDK) using HKDF-SHA256 from the PRF output
export async function derivePDK(prfOutput: ArrayBufferLike, credentialId: string): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(prfOutput) as any,
    { name: "HKDF" },
    false,
    ["deriveKey"]
  );

  const saltBytes = new TextEncoder().encode(credentialId);
  const infoBytes = new TextEncoder().encode("Passkey Derived Key v1");

  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: saltBytes as any,
      info: infoBytes as any
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// Encrypt the MEK with a derived key (PDK or RecoveryDK)
export async function encryptMEK(mekBytes: Uint8Array, key: CryptoKey): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as any },
    key,
    mekBytes as any
  );
  return {
    ciphertext: arrayBufferToBase64(ciphertextBuffer),
    iv: arrayBufferToBase64(iv.buffer)
  };
}

// Decrypt the MEK with a derived key (PDK or RecoveryDK)
export async function decryptMEK(ciphertextBase64: string, ivBase64: string, key: CryptoKey): Promise<Uint8Array> {
  const iv = new Uint8Array(base64ToArrayBuffer(ivBase64));
  const ciphertext = base64ToArrayBuffer(ciphertextBase64);
  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as any },
    key,
    ciphertext
  );
  return new Uint8Array(decryptedBuffer);
}

// Generate the 120-bit entropy human-readable recovery key
// VLT-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX (24 characters, base32 alphabet without ambiguous characters)
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // No 0, 1, I, O

export function generateRecoveryKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  let chars = "";
  for (let i = 0; i < 24; i++) {
    chars += ALPHABET[bytes[i] % ALPHABET.length];
  }
  const parts = [
    "VLT",
    chars.slice(0, 4),
    chars.slice(4, 8),
    chars.slice(8, 12),
    chars.slice(12, 16),
    chars.slice(16, 20),
    chars.slice(20, 24)
  ];
  return parts.join("-");
}

// Derive the Recovery Derived Key (RecoveryDK) using PBKDF2-HMAC-SHA256 from the Recovery Key
export async function deriveRecoveryDK(recoveryKey: string, salt: Uint8Array): Promise<CryptoKey> {
  const cleanKey = recoveryKey.replace(/[^A-Z0-9]/gi, "").toUpperCase();
  
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(cleanKey) as any,
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: salt as any,
      iterations: 100000
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// Encrypt a single vault string field using MEK
export async function encryptField(plaintext: string, mekKey: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as any },
    mekKey,
    encoded as any
  );
  
  const payload = {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv.buffer)
  };
  
  return JSON.stringify(payload);
}

// Decrypt a single vault string field using MEK
export async function decryptField(encryptedJson: string, mekKey: CryptoKey): Promise<string> {
  if (!encryptedJson) return "";
  try {
    const payload = JSON.parse(encryptedJson);
    if (!payload.ciphertext || !payload.iv) {
      throw new Error("Invalid payload format");
    }
    const iv = new Uint8Array(base64ToArrayBuffer(payload.iv));
    const ciphertext = base64ToArrayBuffer(payload.ciphertext);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv as any },
      mekKey,
      ciphertext
    );
    return new TextDecoder().decode(decrypted);
  } catch (err) {
    console.error("Failed to decrypt field:", err);
    return "[Decryption Error]";
  }
}
