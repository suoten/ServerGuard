// ServerGuard Service Worker
// 策略：
//   - HTML 导航请求：network-first（确保拿到最新 index.html）
//   - JS/CSS 等带哈希的静态资源：network-first（确保拿到最新版本，离线时降级到缓存）
//   - API 请求：network-first（离线时降级）
//
// 重要：所有资源都是 network-first，确保部署新版后浏览器立即拿到新资源
// 带哈希的文件名在内容变更时会变，所以不会缓存到旧内容

const CACHE_VERSION = 'v7';
const CACHE_NAME = `serverguard-${CACHE_VERSION}`;
const STATIC_CACHE = `serverguard-static-${CACHE_VERSION}`;

// 静态资源列表
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

// 激活：清理所有旧版本缓存 + 接管所有客户端
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(
        names
          .filter((name) => name !== CACHE_NAME && name !== STATIC_CACHE)
          .map((name) => {
            console.log('[SW] Deleting old cache:', name);
            return caches.delete(name);
          })
      )
    )
  );
  self.clients.claim();
});

// 判断是否为 HTML 导航请求
function isNavigationRequest(request) {
  return request.mode === 'navigate' ||
    (request.headers.get('accept') || '').includes('text/html');
}

// 判断是否为可缓存的同源 GET 请求
function isCacheable(request) {
  if (request.method !== 'GET') return false;
  if (!request.url.startsWith('http')) return false;
  try {
    const url = new URL(request.url);
    if (url.origin !== self.location.origin) return false;
  } catch (e) {
    return false;
  }
  return true;
}

// fetch 拦截
self.addEventListener('fetch', (event) => {
  const { request } = event;

  // 非 GET 请求：直接透传，不拦截
  if (request.method !== 'GET') {
    return;
  }

  // 非 http/https 协议：不拦截
  if (!request.url.startsWith('http')) {
    return;
  }

  // API 请求：network-first
  if (request.url.includes('/api/')) {
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
          }
          return response;
        })
        .catch(() => {
          return caches.match(request).then((cached) => {
            if (cached) return cached;
            return new Response(
              JSON.stringify({ error: 'offline', message: '当前离线，数据可能不是最新的' }),
              { status: 503, headers: { 'Content-Type': 'application/json' } }
            );
          });
        })
    );
    return;
  }

  // HTML 导航请求 + 同源静态资源：统一 network-first
  // 先从网络获取最新版本，成功则缓存并返回；失败时降级到缓存
  if (isNavigationRequest(request) || isCacheable(request)) {
    event.respondWith(
      fetch(request)
        .then((response) => {
          // 成功：缓存一份并返回
          if (response && (response.status === 200 || response.ok)) {
            const clone = response.clone();
            const cacheName = isNavigationRequest(request) ? STATIC_CACHE : STATIC_CACHE;
            caches.open(cacheName).then((cache) => cache.put(request, clone));
          }
          return response;
        })
        .catch(() => {
          // 网络失败：尝试返回缓存
          return caches.match(request).then((cached) => {
            if (cached) return cached;
            // 无缓存：对导航请求返回缓存的 index.html，对静态资源返回 504
            if (isNavigationRequest(request)) {
              return caches.match('/index.html');
            }
            console.warn('[SW] Resource offline and not cached:', request.url);
            return new Response('', {
              status: 504,
              statusText: 'Gateway Timeout',
              headers: { 'Content-Type': 'text/plain' }
            });
          });
        })
    );
    return;
  }
});
