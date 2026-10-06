const ALLOWED_ORIGINS=["https://leeuw008-nl.github.io","https://gps-puzzeltocht.leeuw008.nl"];
const COOKIE="gps_puzzel_auth";
const MAX_AGE=60*60*8;
const ROUTES_KEY="routes:index";

function b64url(bytes){let s="";for(const b of bytes)s+=String.fromCharCode(b);return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")}
async function sign(value,secret){
 const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
 return b64url(new Uint8Array(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(value))));
}
async function makeToken(secret){
 const payload=b64url(new TextEncoder().encode(JSON.stringify({role:"maker",exp:Math.floor(Date.now()/1000)+MAX_AGE})));
 return payload+"."+await sign(payload,secret);
}
async function validToken(token,secret){
 try{
  const [payload,sig]=token.split(".");
  if(!payload||!sig||!secret)return false;
  const expected=await sign(payload,secret);
  if(sig!==expected)return false;
  const padded=payload.replace(/-/g,"+").replace(/_/g,"/")+"===".slice((payload.length+3)%4);
  const p=JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(padded),c=>c.charCodeAt(0))));
  return p.role==="maker"&&p.exp>Date.now()/1000;
 }catch{return false}
}
function baseHeaders(origin){
 const allowed=ALLOWED_ORIGINS.includes(origin)?origin:ALLOWED_ORIGINS[0];
 return{"Access-Control-Allow-Origin":allowed,"Access-Control-Allow-Credentials":"true","Access-Control-Allow-Headers":"Content-Type","Access-Control-Allow-Methods":"GET,POST,DELETE,OPTIONS","Cache-Control":"no-store","Content-Type":"application/json"}
}
function json(body,status=200,extra={},origin){return new Response(JSON.stringify(body),{status,headers:{...baseHeaders(origin),...extra}})}
function parseCookie(request){
 const cookie=request.headers.get("Cookie")||"";
 return(cookie.match(new RegExp(COOKIE+"=([^;]+)"))||[])[1]||"";
}
async function readRoutes(env){
 if(!env.ROUTES)return null;
 try{return JSON.parse(await env.ROUTES.get(ROUTES_KEY)||"[]")}catch{return []}
}
async function writeRoutes(env,routes){
 if(!env.ROUTES)throw new Error("ROUTES binding ontbreekt");
 await env.ROUTES.put(ROUTES_KEY,JSON.stringify(routes));
}

export default{
 async fetch(request,env){
  const origin=request.headers.get("Origin")||"";
  if(request.method==="OPTIONS")return new Response(null,{status:204,headers:baseHeaders(origin)});
  const url=new URL(request.url);
  if(url.pathname==="/health")return json({ok:true},200,{},origin);

  const authenticated=await validToken(parseCookie(request),env.SESSION_SECRET||"");

  if(url.pathname==="/auth/status")return json({authenticated},200,{},origin);

  if(url.pathname==="/auth/login"&&request.method==="POST"){
   let body={};try{body=await request.json()}catch{}
   if(!env.AUTH_PASSWORD||body.password!==env.AUTH_PASSWORD)return json({authenticated:false},401,{},origin);
   const value=await makeToken(env.SESSION_SECRET);
   return json({authenticated:true},200,{"Set-Cookie":COOKIE+"="+value+"; Max-Age="+MAX_AGE+"; Path=/; Secure; HttpOnly; SameSite=None"},origin);
  }

  if(url.pathname==="/auth/logout"&&request.method==="POST"){
   return json({authenticated:false},200,{"Set-Cookie":COOKIE+"=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=None"},origin);
  }

  if(url.pathname==="/routes"&&request.method==="GET"){
   const routes=await readRoutes(env);
   if(routes===null)return json({error:"Routeopslag is nog niet geconfigureerd."},503,{},origin);
   return json({routes},200,{},origin);
  }

  if(url.pathname==="/routes"&&request.method==="POST"){
   if(!authenticated)return json({error:"Niet ingelogd."},401,{},origin);
   let route=null;try{route=await request.json()}catch{}
   if(!route||typeof route.name!=="string"||!Array.isArray(route.stages))return json({error:"Ongeldige route."},400,{},origin);
   const routes=await readRoutes(env);
   if(routes===null)return json({error:"Routeopslag is nog niet geconfigureerd."},503,{},origin);
   const clean={...route,name:route.name.trim()};
   const idx=routes.findIndex(r=>r&&r.name===clean.name);
   if(idx>=0)routes[idx]=clean;else routes.push(clean);
   await writeRoutes(env,routes);
   return json({ok:true,route:clean,routes},200,{},origin);
  }

  if(url.pathname==="/routes"&&request.method==="DELETE"){
   if(!authenticated)return json({error:"Niet ingelogd."},401,{},origin);
   const name=url.searchParams.get("name")||"";
   if(!name)return json({error:"Route naam ontbreekt."},400,{},origin);
   const routes=await readRoutes(env);
   if(routes===null)return json({error:"Routeopslag is nog niet geconfigureerd."},503,{},origin);
   const next=routes.filter(r=>r&&r.name!==name);
   await writeRoutes(env,next);
   return json({ok:true,routes:next},200,{},origin);
  }

  return json({error:"Not found"},404,{},origin);
 }
};