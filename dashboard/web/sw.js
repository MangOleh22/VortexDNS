// VortexDNS Service Worker — PWA Offline & Cache Strategy
const CACHE_NAME = 'vortexdns-v1';
const STATIC_ASSETS = [
  '/',
  '/style.css',
  '/app.js',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png'
];

// Install: cache semua aset statis
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(STATIC_ASSETS);
    }).then(() => self.skipWaiting())
  );
});

// Activate: hapus cache lama
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

// Fetch strategy:
// - API endpoints (/api/*) → Network First (data harus selalu segar/real-time)
// - Static assets → Cache First dengan fallback ke network
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // API: selalu ambil dari network (real-time data)
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(event.request).catch(() => {
        // Jika offline, kembalikan respons JSON placeholder
        return new Response(JSON.stringify({
          error: 'offline',
          message: 'VortexDNS tidak terjangkau. Pastikan server berjalan.'
        }), {
          headers: { 'Content-Type': 'application/json' }
        });
      })
    );
    return;
  }

  // SSE stream: jangan di-cache, langsung ke network
  if (url.pathname === '/api/logs/stream') {
    event.respondWith(fetch(event.request));
    return;
  }

  // Static assets: Cache First
  event.respondWith(
    caches.match(event.request).then(cached => {
      if (cached) return cached;
      return fetch(event.request).then(response => {
        // Simpan ke cache jika respons OK
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
        return response;
      });
    })
  );
});

// Background Sync: beritahu client saat kembali online
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
