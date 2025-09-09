const CACHE_NAME = "shelfsmart-cache-v1";

// ✅ Match your actual files
const urlsToCache = [
  "/",
  "/static/css/styles.css",   // fixed name
  "/static/js/main.js",
  "/static/icons/ShelfSmart.png", // match manifest
  "/static/icons/ShelfSmart.png"
];

// Install event: cache files
self.addEventListener("install", event => {
  console.log("✅ Service Worker Installed");
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log("📦 Caching files...");
        return cache.addAll(urlsToCache);
      })
      .catch(err => console.error("❌ Failed to cache files:", err))
  );
  self.skipWaiting();
});

// Activate event: clean old caches
self.addEventListener("activate", event => {
  console.log("✅ Service Worker Activated");
  event.waitUntil(
    caches.keys().then(keys => {
      return Promise.all(
        keys.map(key => {
          if (key !== CACHE_NAME) {
            console.log("🗑️ Removing old cache:", key);
            return caches.delete(key);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// Fetch event: serve cached files if offline
self.addEventListener("fetch", event => {
  event.respondWith(
    caches.match(event.request).then(response => {
      if (response) {
        console.log("📂 Serving from cache:", event.request.url);
        return response;
      }
      return fetch(event.request).then(networkResponse => {
        return networkResponse;
      }).catch(() => {
        // Fallback when offline
        if (event.request.mode === "navigate") {
          return caches.match("/");
        }
      });
    })
  );
});
