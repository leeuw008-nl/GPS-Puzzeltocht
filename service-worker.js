const CACHE='gps-puzzeltocht-v7';
const ASSETS=['./','./index.html','./manifest.json'];
self.addEventListener('install',e=>e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)).then(()=>self.skipWaiting())));
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('fetch',e=>{
 if(e.request.method!=='GET')return;
 e.respondWith(fetch(e.request).then(res=>{
  const copy=res.clone(); caches.open(CACHE).then(c=>c.put(e.request,copy)); return res;
 }).catch(()=>caches.match(e.request)));
});