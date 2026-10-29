import { createRemoteJWKSet, jwtVerify } from 'jose';

const IMG = /^(\d{8,18})(?:\.(?:jpe?g|png|webp|gif))?$/i;
const ALLOWED = new Set(['image/jpeg','image/png','image/webp','image/gif']);
const json = (data, status=200) => new Response(JSON.stringify(data), {status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'}});
const denial = (status=403) => new Response(status===404?'Not found':'Forbidden',{status,headers:{'cache-control':'no-store','x-content-type-options':'nosniff'}});
const teamJwks = new Map();
async function authorized(request, env) {
  if (!env.CF_ACCESS_TEAM_DOMAIN || !env.CF_ACCESS_AUD || env.CF_ACCESS_TEAM_DOMAIN.startsWith('REPLACE_') || env.CF_ACCESS_AUD.startsWith('REPLACE_')) return false;
  const token = request.headers.get('Cf-Access-Jwt-Assertion');
  if (!token) return false;
  const issuer = `https://${env.CF_ACCESS_TEAM_DOMAIN.replace(/^https?:\/\//,'').replace(/\/$/,'')}`;
  let jwks = teamJwks.get(issuer);
  if (!jwks) { jwks = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`)); teamJwks.set(issuer,jwks); }
  try { await jwtVerify(token,jwks,{issuer,audience:env.CF_ACCESS_AUD}); return true; } catch { return false; }
}
function adminHtml() { return `<!doctype html><html lang="he" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Shoham Images - ניהול</title><style>body{font-family:Arial,sans-serif;background:#f4f6fa;margin:0;color:#1b2c44}header{background:#16253d;color:white;padding:18px 28px}main{max-width:1000px;margin:auto;padding:25px}section{background:white;padding:22px;border-radius:13px;margin-bottom:18px;box-shadow:0 2px 10px #172c4112}input,button{padding:12px;border-radius:8px;border:1px solid #cbd5e1}button{background:#155eef;color:white;cursor:pointer}button:disabled{opacity:.5}table{border-collapse:collapse;width:100%;text-align:right}th,td{padding:11px;border-bottom:1px solid #e2e8f0}small{color:#52627a}code{direction:ltr;display:inline-block}.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}#status{white-space:pre-wrap}</style></head><body><header><strong>Shoham Images | ניהול CDN</strong></header><main><section><h2>העלאת תמונה ידנית</h2><p><small>שם הקובץ חייב להיות דגם וקוד צבע ברצף, למשל 171204412.jpg. קבצים עם אותו מזהה יוחלפו.</small></p><form id="upload" class="row"><input type="file" id="file" accept="image/jpeg,image/png,image/webp,image/gif" required><button>העלאה</button></form><p id="status"></p></section><section><h2>חיפוש תמונה</h2><div class="row"><input id="model" placeholder="171204412" inputmode="numeric"><button id="search">חפש</button></div><p id="result"></p></section><section><h2>רשימת תמונות (למנהלים בלבד)</h2><button id="list">טען רשימה</button><p><small>הרשימה אינה זמינה בדומיין הציבורי.</small></p><div id="table"></div></section></main><script>
const q=id=>document.getElementById(id);
q('upload').onsubmit=async e=>{e.preventDefault();let f=q('file').files[0]; if(!f)return; q('status').textContent='מעלה...';try{let r=await fetch('/admin/api/upload/'+encodeURIComponent(f.name),{method:'PUT',headers:{'content-type':f.type},body:f});q('status').textContent=JSON.stringify(await r.json(),null,2)}catch(e){q('status').textContent=e.message}};
q('search').onclick=()=>{const id=q('model').value.trim();q('result').textContent='';if(!/^\\d{8,18}$/.test(id)){q('result').textContent='יש להזין מזהה מספרי';return;}const a=document.createElement('a');a.href='https://cdn.kiwi-kids.co.il/'+id;a.target='_blank';a.rel='noopener noreferrer';a.textContent=a.href;q('result').append(a)};
q('list').onclick=async()=>{const r=await fetch('/admin/api/list?limit=100');if(!r.ok){q('table').textContent='שגיאה בטעינה';return;}const data=await r.json();const div=q('table');div.replaceChildren();const table=document.createElement('table');let tr=document.createElement('tr');for(const title of ['שם','גודל בבייטים','תאריך']){let th=document.createElement('th');th.textContent=title;tr.append(th)}table.append(tr);for(const item of data.objects){let row=document.createElement('tr');for(const val of [item.key,String(item.size),item.uploaded]){let td=document.createElement('td');td.textContent=val;row.append(td)}table.append(row)}div.append(table);if(data.truncated){let p=document.createElement('p');p.textContent='יש עוד תמונות. ניתן להשתמש בסינון prefix דרך ה-API';div.append(p)}};
</script></body></html>`; }
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const host=url.hostname.toLowerCase();
    if (host===env.ADMIN_HOST.toLowerCase()) {
      if (!await authorized(request,env)) return denial();
      if (request.method==='GET' && url.pathname==='/') return new Response(adminHtml(),{headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','content-security-policy':"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' https://cdn.kiwi-kids.co.il; base-uri 'none'; frame-ancestors 'none'"}});
      if (request.method==='GET' && url.pathname==='/admin/api/list') {
        const prefix=url.searchParams.get('prefix')||'';
        if (prefix && !/^\d{1,18}$/.test(prefix)) return json({error:'Invalid prefix'},400);
        const result=await env.IMAGES.list({limit:Math.min(Number(url.searchParams.get('limit'))||100,1000),prefix});
        return json({objects:result.objects.map(x=>({key:x.key,size:x.size,uploaded:x.uploaded?.toISOString()})),truncated:result.truncated,cursor:result.truncated?result.cursor:null});
      }
      if (request.method==='PUT' && url.pathname.startsWith('/admin/api/upload/')) {
        const name=decodeURIComponent(url.pathname.slice('/admin/api/upload/'.length));
        const m=name.match(IMG); if (!m) return json({error:'Filename must be numeric model+color'},400);
        const type=request.headers.get('content-type')?.split(';')[0]?.toLowerCase();
        if (!ALLOWED.has(type)) return json({error:'Unsupported Content-Type'},415);
        const length=Number(request.headers.get('content-length'));
        if (!Number.isFinite(length)||length<=0||length>15*1024*1024) return json({error:'File size must be 1 byte to 15MB'},413);
        const bytes=await request.arrayBuffer(); if(bytes.byteLength>15*1024*1024) return json({error:'Too large'},413);
        const b=new Uint8Array(bytes);const jpg=b[0]===0xff&&b[1]===0xd8&&b[2]===0xff;const png=b[0]===137&&b[1]===80&&b[2]===78&&b[3]===71;const gif=String.fromCharCode(...b.slice(0,3))==='GIF';const webp=String.fromCharCode(...b.slice(0,4))==='RIFF'&&String.fromCharCode(...b.slice(8,12))==='WEBP';
        if (!((type==='image/jpeg'&&jpg)||(type==='image/png'&&png)||(type==='image/gif'&&gif)||(type==='image/webp'&&webp))) return json({error:'File bytes do not match image type'},415);
        await env.IMAGES.put(m[1],bytes,{httpMetadata:{contentType:type},customMetadata:{source:'manual',originalFile:name}});
        return json({ok:true,id:m[1],url:`https://${env.CDN_HOST}/${m[1]}`});
      }
      return denial(404);
    }
    if (host!==env.CDN_HOST.toLowerCase()) return denial(404);
    if (!['GET','HEAD'].includes(request.method)) return new Response('Method not allowed',{status:405,headers:{allow:'GET, HEAD'}});
    if (url.search) return denial(404);
    const match=url.pathname.match(/^\/(\d{8,18})(?:\.(?:jpg|jpeg|png|webp|gif))?$/i);
    if (!match) return denial();
    const key=match[1];
    const object=await env.IMAGES.get(key);
    if (!object) return denial(404);
    const headers=new Headers(); object.writeHttpMetadata(headers);
    if (!ALLOWED.has(headers.get('content-type'))) return denial(404);
    headers.set('etag',object.httpEtag);
    headers.set('cache-control','public, max-age=300, s-maxage=300');
    headers.set('x-content-type-options','nosniff');
    headers.set('content-security-policy',"default-src 'none'; sandbox");
    return new Response(request.method==='HEAD'?null:object.body,{status:200,headers});
  }
};
