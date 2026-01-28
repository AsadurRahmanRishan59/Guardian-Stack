// lib/device/fingerprint.ts
const DEVICE_ID_KEY = 'device_id';

export function getOrCreateDeviceId(): string {
  if (typeof window === 'undefined') return 'server-side';

  let deviceId = localStorage.getItem(DEVICE_ID_KEY);

  if (!deviceId) {
    deviceId = crypto.randomUUID();
    localStorage.setItem(DEVICE_ID_KEY, deviceId);
    console.log('🆔 New device ID created:', deviceId);
  }

  return deviceId;
}

export function clearDeviceId(): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(DEVICE_ID_KEY);
}

/**
 * Get current device ID without creating one
 */
export function getDeviceId(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(DEVICE_ID_KEY);
}