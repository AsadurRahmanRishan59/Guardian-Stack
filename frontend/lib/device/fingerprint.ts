// lib/device/fingerprint.ts
const DEVICE_ID_KEY = 'device_id';

export function getOrCreateDeviceId(): string {
  if (typeof window === 'undefined') return 'server-side';
  
  let deviceId = localStorage.getItem(DEVICE_ID_KEY);
  
  if (!deviceId) {
    deviceId = crypto.randomUUID();
    localStorage.setItem(DEVICE_ID_KEY, deviceId);
  }
  
  return deviceId;
}

export function clearDeviceId(): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(DEVICE_ID_KEY);
}