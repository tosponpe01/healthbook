/* สมุดสุขภาพ: ให้เปิดแอปได้แม้ไม่มีเน็ต
 * หน้าเว็บ: ดึงของใหม่ก่อน (ได้เวอร์ชันล่าสุดเสมอเมื่อมีเน็ต) ไม่มีเน็ตค่อยใช้ที่เก็บไว้
 * ไอคอน ฟอนต์ demo.js: ใช้ที่เก็บไว้ก่อน แล้วแอบอัปเดตเบื้องหลัง
 * ไม่ยุ่งกับการส่งข้อมูลไประบบของโรงเรียน (script.google.com) */
var CACHE = 'healthbook-v2';
var SHELL = ['./', 'index.html', 'manifest.webmanifest', 'icon-192.png', 'icon-512.png'];

self.addEventListener('install', function (e) {
  e.waitUntil(caches.open(CACHE).then(function (c) {
    return Promise.all(SHELL.map(function (u) { return c.add(u).catch(function () {}); }));
  }).then(function () { return self.skipWaiting(); }));
});

self.addEventListener('activate', function (e) {
  e.waitUntil(caches.keys().then(function (keys) {
    return Promise.all(keys.filter(function (k) { return k !== CACHE; }).map(function (k) { return caches.delete(k); }));
  }).then(function () { return self.clients.claim(); }));
});

function networkFirst(req) {
  return caches.open(CACHE).then(function (c) {
    return new Promise(function (resolve) {
      var done = false;
      var fallback = function () { c.match(req, { ignoreSearch: true }).then(function (r) { if (!done) { done = true; resolve(r || c.match('index.html')); } }); };
      var timer = setTimeout(fallback, 6000);
      fetch(req).then(function (res) {
        clearTimeout(timer);
        if (res && res.ok) c.put(req.mode === 'navigate' ? 'index.html' : req, res.clone());
        if (!done) { done = true; resolve(res); }
      }, function () { clearTimeout(timer); fallback(); });
    });
  });
}
function staleWhileRevalidate(req) {
  return caches.open(CACHE).then(function (c) {
    return c.match(req).then(function (hit) {
      var net = fetch(req).then(function (res) { if (res && (res.ok || res.type === 'opaque')) c.put(req, res.clone()); return res; }, function () { return hit; });
      return hit || net;
    });
  });
}

self.addEventListener('fetch', function (e) {
  var req = e.request, url = new URL(req.url);
  if (req.method !== 'GET') return;
  if (/script\.google(usercontent)?\.com$/.test(url.hostname)) return;
  if (url.origin === location.origin) {
    if (req.mode === 'navigate' || /\/(index\.html)?$/.test(url.pathname)) { e.respondWith(networkFirst(req)); return; }
    e.respondWith(staleWhileRevalidate(req));
    return;
  }
  if (/fonts\.(googleapis|gstatic)\.com$/.test(url.hostname)) e.respondWith(staleWhileRevalidate(req));
});
