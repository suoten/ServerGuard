// ServerGuard Service Worker
// 策略：API 请求走 network-first（离线时降级），静态资源走 cache-first

const CACHE_NAME = 'serverguard-v3';
const STATIC_CACHE = 'serverguard-static-v3';

// 静态资源列表（构建后由 vite 注入实际哈希文件名）
const PRECACHE_URLS = [
  '/',
  '/index.html',
  '/favicon.svg',
  '/manifest.json',
];

// 安装：预缓存关键静态资源
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE).then((cache) => cache.addAll(PRECACHE_URLS))
  );
  self.skipWaiting();
});

// 激活：清理旧缓存
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(
        names
          .filter((name) => name !== CACHE_NAME && name !== STATIC_CACHE)
          .map((name) => caches.delete(name))
      )
    )
  );
  self.clients.claim();
});

// fetch 拦截
self.addEventListener('fetch', (event) => {
  const { request } = event;

  // API 请求：network-first（先尝试网络，失败时返回缓存或离线提示）
  if (request.url.includes('/api/')) {
    event.respondWith(
      fetch(request)
        .then((response) => {
          // 成功：缓存一份并返回
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
          return response;
        })
        .catch(() => {
          // 离线：尝试返回缓存
          return caches.match(request).then((cached) => {
            if (cached) return cached;
            // 无缓存：返回离线标记的 JSON
            return new Response(
              JSON.stringify({ error: 'offline', message: '当前离线，数据可能不是最新的' }),
              { status: 503, headers: { 'Content-Type': 'application/json' } }
            );
          });
        })
    );
    return;
  }

  // 静态资源：cache-first（先查缓存，未命中再请求网络）
  if (request.method === 'GET') {
    event.respondWith(
      caches.match(request).then((cached) => {
        if (cached) return cached;
        return fetch(request).then((response) => {
          if (!response || response.status !== 200) return response;
          const clone = response.clone();
          caches.open(STATIC_CACHE).then((cache) => cache.put(request, clone));
          return response;
        });
      })
    );
  }
});

// 后台同步：离线操作队列
self.addEventListener('sync', (event) => {
  if (event.tag === 'sg-offline-queue') {
    event.waitUntil(replayOfflineQueue());
  }
});

async function replayOfflineQueue() {
  // 从 IndexedDB 读取离线操作队列并逐个重放
  // 实现简化版：实际需配合 IndexedDB 存储
  const cache = await caches.open(CACHE_NAME);
  const keys = await cache.keys();
  for (const req of keys) {
    if (req.method === 'POST') {
      try {
        await fetch(req);
        await cache.delete(req);
      } catch {
        // 仍然离线，下次重试
      }
    }
  }
}
