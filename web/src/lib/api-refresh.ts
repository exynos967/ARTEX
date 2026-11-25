import { RefreshCooldownGate, RefreshCoordinator, RequestCache, type RefreshOptions } from "./api-cache";

export const EVENT_COALESCE_MS = 2_500;
export const FOCUS_REFRESH_COOLDOWN_MS = 10_000;
export const RESUME_REFRESH_COOLDOWN_MS = 5_000;

export const apiCache = new RequestCache();
const coordinator = new RefreshCoordinator();
const refreshCooldown = new RefreshCooldownGate({
  focusMs: FOCUS_REFRESH_COOLDOWN_MS,
  resumeMs: RESUME_REFRESH_COOLDOWN_MS,
});
let subscribers = 0;
let removeListeners: (() => void) | undefined;
let session: string | null | undefined;
let eventTimer: ReturnType<typeof setTimeout> | undefined;
const eventKeys = new Set<string>();

export function syncApiSession(token: string | null): void {
  if (session === token) return;
  session = token;
  apiCache.clear();
}

export function clearApiCache(): void {
  session = undefined;
  if (eventTimer !== undefined) {
    clearTimeout(eventTimer);
    eventTimer = undefined;
    eventKeys.clear();
  }
  refreshCooldown.reset();
  apiCache.clear();
  coordinator.invalidate();
}

export function invalidateApiData(keys?: readonly string[]): void {
  apiCache.invalidate(keys);
  coordinator.invalidate(keys);
}

// Activity can arrive for every streamed token. Coalesce it into at most one
// invalidation per 2.5 seconds while preserving the last batch during long streams.
export function notifyApiEvent(keys: readonly string[]): void {
  for (const key of keys) eventKeys.add(key);
  if (eventTimer !== undefined) return;
  eventTimer = setTimeout(() => {
    eventTimer = undefined;
    const batch = [...eventKeys];
    eventKeys.clear();
    if (batch.length > 0) invalidateApiData(batch);
  }, EVENT_COALESCE_MS);
}

function attachBrowserListeners(): () => void {
  if (typeof document === "undefined") return () => undefined;
  let wasVisible = document.visibilityState !== "hidden";
  coordinator.setVisible(wasVisible, false);
  const visibility = () => {
    const visible = document.visibilityState !== "hidden";
    if (!visible) {
      wasVisible = false;
      coordinator.setVisible(false);
      return;
    }
    const returningFromHidden = !wasVisible;
    wasVisible = true;
    const shouldRefresh = returningFromHidden && refreshCooldown.allow("resume");
    if (shouldRefresh) apiCache.invalidate();
    coordinator.setVisible(true, shouldRefresh);
  };
  const onFocus = () => {
    if (document.visibilityState !== "hidden" && refreshCooldown.allow("focus")) invalidateApiData();
  };
  const onOnline = () => {
    if (document.visibilityState !== "hidden" && refreshCooldown.allow("online")) invalidateApiData();
  };
  const storage = (event: StorageEvent) => {
    if (event.key === "artex_token" || event.key === null) clearApiCache();
  };
  document.addEventListener("visibilitychange", visibility);
  window.addEventListener("focus", onFocus);
  window.addEventListener("online", onOnline);
  window.addEventListener("storage", storage);
  return () => {
    document.removeEventListener("visibilitychange", visibility);
    window.removeEventListener("focus", onFocus);
    window.removeEventListener("online", onOnline);
    window.removeEventListener("storage", storage);
  };
}

export function subscribeRefresh(load: () => unknown | Promise<unknown>, options?: RefreshOptions): () => void {
  if (++subscribers === 1) removeListeners = attachBrowserListeners();
  const unsubscribe = coordinator.subscribe(load, options);
  let stopped = false;
  return () => {
    if (stopped) return;
    stopped = true;
    unsubscribe();
    if (--subscribers === 0) {
      removeListeners?.();
      removeListeners = undefined;
    }
  };
}
