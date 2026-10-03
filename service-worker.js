const CACHE='gps-puzzeltocht-v1';
const ASSETS=['./','./index.html','./manifest.json'];
self.addEventListener('install',e=>e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)).then(()=>self.skipWaiting())));
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('fetch',e=>{
 if(e.request.method!=='GET')return;
 e.respondWith(caches.match(e.request).then(cached=>cached||fetch(e.request).then(res=>{
  const copy=res.clone(); caches.open(CACHE).then(c=>c.put(e.request,copy)); return res;
 }).catch(()=>cached)));
});