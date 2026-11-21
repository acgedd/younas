// Service worker for the installed app. It keeps the app shell (the page, CSS, JavaScript, fonts and
// icons under /app) available offline, and nothing else.
//
// RULE: it never touches an API response or a file's contents. Anything that is not a GET of the
// shell falls through untouched: no respondWith, so the browser handles it as if this worker did not
// exist. tests/js/sw_scenarios.mjs pins this. The shell holds no user data and no token.
//
// Network first, so an update reaches the phone on the next launch; the cache is only for when the
// server cannot be reached.

const CACHE = "yournas-shell-v1";
const NETWORK_TIMEOUT_MS = 8000;

const SHELL = [
  "/app/",
  "/app/s/manifest.webmanifest",
  "/app/s/css/fonts.css",
  "/app/s/css/app.css",
  "/app/s/css/additions.css",
  "/app/s/vendor/motion-12.23.12.js",
  "/app/s/js/api.js",
  "/app/s/js/covers.js",
  "/app/s/js/dom.js",
  "/app/s/js/format.js",
  "/app/s/js/main.js",
  "/app/s/js/motion.js",
  "/app/s/js/preview.js",
  "/app/s/js/shell.js",
  "/app/s/js/store.js",
  "/app/s/js/thumbs.js",
  "/app/s/js/transfers.js",
  "/app/s/js/wakelock.js",
  "/app/s/js/views/gate.js",
  "/app/s/js/views/home.js",
  "/app/s/js/views/library.js",
  "/app/s/js/views/photos.js",
  "/app/s/js/views/status.js",
  "/app/s/js/views/storage.js",
  "/app/s/js/views/upload.js",
  "/app/s/fonts/DMMono-Medium.woff2",
  "/app/s/fonts/DMMono-Regular.woff2",
  "/app/s/fonts/EternalBloom.otf",
  "/app/s/fonts/Redaction10-Bold.ttf",
  "/app/s/fonts/Redaction10-Regular.ttf",
  "/app/s/img/icon-180.png",
  "/app/s/img/icon-192.png",
  "/app/s/img/icon-32.png",
  "/app/s/img/icon-512.png",
  "/app/s/img/noise.svg",
];

function isShell(request) {
  if (request.method !== "GET") return false;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return false;
  return url.pathname === "/app" || url.pathname === "/app/" || url.pathname.startsWith("/app/s/");
}

async function fromNetworkOrCache(request) {
  const cache = await caches.open(CACHE);
  // By path alone: one visit to /app/?x must not leave a copy that later answers for /app/.
  const path = new URL(request.url).pathname;
  const key = path === "/app" ? "/app/" : path;
  const cached = await cache.match(key);
  const timeout = new AbortController();
  // Without a cached copy a slow network is still better than an error.
  const timer = cached ? setTimeout(() => timeout.abort(), NETWORK_TIMEOUT_MS) : 0;
  try {
    const response = await fetch(request, { signal: timeout.signal });
    if (response.ok && response.type === "basic") await cache.put(key, response.clone());
    return response;
  } catch (err) {
    if (cached) return cached;
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE);
      await cache.addAll(SHELL);
      await self.skipWaiting();
    })(),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      const names = await caches.keys();
      await Promise.all(names.filter((name) => name !== CACHE).map((name) => caches.delete(name)));
      await self.clients.claim();
    })(),
  );
});

self.addEventListener("fetch", (event) => {
  if (isShell(event.request)) event.respondWith(fromNetworkOrCache(event.request));
});
