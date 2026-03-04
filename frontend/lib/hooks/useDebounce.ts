// hooks/useDebounce.ts
import { useState, useEffect } from "react";

/**
 * Returns a debounced copy of `value` that only updates after
 * `delay` ms of inactivity. Use this to avoid firing API calls
 * on every keystroke in search/filter inputs.
 *
 * @param value  The value to debounce (typically a string from an input)
 * @param delay  Milliseconds to wait after the last change (default: 400ms)
 */
export function useDebounce<T>(value: T, delay = 400): T {
  const [debounced, setDebounced] = useState<T>(value);

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);

  return debounced;
}