// Keeps the screen on while something is uploading. iOS suspends a page whose screen locks, so this
// is what lets a long upload finish unattended. The browser drops the lock whenever the page is
// hidden, so it is taken again when the page comes back.

export const wakeLockSupported = () => typeof navigator !== "undefined" && "wakeLock" in navigator;

export function createWakeLock() {
  let wanted = false;
  let sentinel = null;
  let asking = false;

  async function sync() {
    if (!wakeLockSupported()) return;
    if (!wanted) {
      const held = sentinel;
      sentinel = null;
      if (held) await held.release().catch(() => {});
      return;
    }
    if (sentinel || asking || document.visibilityState !== "visible") return;
    asking = true;
    try {
      sentinel = await navigator.wakeLock.request("screen");
      sentinel.addEventListener("release", () => {
        sentinel = null;
      });
      if (!wanted) await sync();
    } catch {
      /* refused (battery saver): uploads still pause and resume */
    } finally {
      asking = false;
    }
  }

  const onVisible = () => sync();
  document.addEventListener("visibilitychange", onVisible);

  return {
    set(value) {
      wanted = value;
      sync();
    },
    destroy() {
      wanted = false;
      document.removeEventListener("visibilitychange", onVisible);
      sync();
    },
  };
}
