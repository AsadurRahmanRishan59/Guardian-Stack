import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const SECRET = process.env.BFF_SECRET_KEY || 'a-very-secret-key-32-chars-long!!'; 
// Ensure the secret is 32 bytes
const KEY = scryptSync(SECRET, 'salt', 32);

export function encryptToken(text: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGORITHM, KEY, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag().toString('hex');
  
  // Format: iv:authTag:encryptedValue
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

export function decryptToken(token: string) {
  const [ivHex, authTagHex, encrypted] = token.split(':');
  
  const decipher = createDecipheriv(ALGORITHM, KEY, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
  
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}