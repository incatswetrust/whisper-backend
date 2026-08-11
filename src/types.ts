export interface NoteRecord {
  id: string;
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
  /** salt for password-derived key component (server-encrypted) or verifier (client-encrypted); null if no password gate */
  salt: Buffer | null;
  hasPassword: boolean;
  /** only set when clientEncrypted, since the server has no key to check a password against via AEAD */
  passwordVerifier: Buffer | null;
  /** true if the client already encrypted the payload before sending it (E2E) */
  clientEncrypted: boolean;
  allowedIp: string | null;
  filename: string | null;
  contentType: string;
  createdAt: number;
  expiresAt: number;
  viewsRemaining: number;
}
