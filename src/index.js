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

// Source credentials encrypted at rest with AES-GCM. Configure SOURCE_ENCRYPTION_KEY
// as a 32-byte random base64 secret using Wrangler secrets, never in source control.
function b64(bytes){ return btoa(String.fromCharCode(...bytes)); }
function unb64(text){return Uint8Array.from(atob(text), c=>c.charCodeAt(0));}
async function encryptSecret(secret, env){
  if(!env.SOURCE_ENCRYPTION_KEY) throw Error('Encryption key not configured');
  const raw=unb64(env.SOURCE_ENCRYPTION_KEY);
  if(raw.byteLength!==32) throw Error('Invalid encryption key');
  const key=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt']);
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const data=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(secret));
  return {cipher:b64(new Uint8Array(data)),iv:b64(iv)};
}
const validSource = p => p && /^[\p{L}\p{N} ._-]{1,80}$/u.test(p.name||'') &&
  ['ftp','sftp'].includes(p.protocol) &&
  typeof p.host==='string' && /^(?!-)[A-Za-z0-9.-]{1,253}$/.test(p.host) &&
  Number.isInteger(p.port) && p.port>=1 && p.port<=65535 &&
  typeof p.source_path==='string' && p.source_path.startsWith('/') && p.source_path.length<=512 &&
  typeof p.username==='string' && p.username.length>0 && p.username.length<=128 &&
  typeof p.password==='string' && p.password.length>0 && p.password.length<=512 &&
  (!p.ssh_fingerprint || /^SHA256:[A-Za-z0-9+/]{32,64}=?$/.test(p.ssh_fingerprint)) &&
  [5,15,30,60,1440].includes(p.interval_minutes);
async function sourceApi(request,env,url) {
  if (!env.DB) return json({error:'Database not bound'},503);
  if(request.method==='GET' && url.pathname==='/admin/api/sources'){
    const {results}=await env.DB.prepare('SELECT id,name,protocol,host,port,source_path,username,ssh_fingerprint,enabled,interval_minutes,created_at,updated_at FROM image_sources ORDER BY created_at DESC').all();
    return json({sources:results});
  }
  if(request.method==='POST' && url.pathname==='/admin/api/sources'){
    if(!env.SOURCE_ENCRYPTION_KEY) return json({error:'Encryption key not configured'},503);
    if(Number(request.headers.get('content-length'))>8192) return json({error:'Payload too large'},413);
    let p;try{p=await request.json()}catch{return json({error:'Invalid JSON'},400)}
    if(typeof p?.source_path==='string') { p.source_path=p.source_path.trim().split(String.fromCharCode(92)).join('/'); if(p.source_path==='') p.source_path='/'; }
    if(!validSource(p)){const errors=[];if(!/^[\\p{L}\\p{N} ._-]{1,80}$/u.test(p?.name||''))errors.push('name');if(!['ftp','sftp'].includes(p?.protocol))errors.push('protocol');if(!/^(?!-)[A-Za-z0-9.-]{1,253}$/.test(p?.host||''))errors.push('host');if(!Number.isInteger(p?.port)||p.port<1||p.port>65535)errors.push('port');if(typeof p?.source_path!=='string'||!p.source_path.startsWith('/')||p.source_path.length>512)errors.push('source_path');if(!p?.username||p.username.length>128)errors.push('username');if(!p?.password||p.password.length>512)errors.push('password');if(![5,15,30,60,1440].includes(p?.interval_minutes))errors.push('interval_minutes');if(p?.ssh_fingerprint&&!/^SHA256:[A-Za-z0-9+/]{32,64}=?$/.test(p.ssh_fingerprint))errors.push('ssh_fingerprint');return json({error:'Invalid source settings',fields:errors},400);}
    if(p.protocol==='sftp' && !p.ssh_fingerprint)return json({error:'SFTP host fingerprint required'},400);
    const encrypted=await encryptSecret(p.password,env);
    const id=crypto.randomUUID();
    await env.DB.prepare('INSERT INTO image_sources (id,name,protocol,host,port,source_path,username,secret_cipher,secret_iv,ssh_fingerprint,enabled,interval_minutes) VALUES (?,?,?,?,?,?,?,?,?,?,0,?)').bind(id,p.name,p.protocol,p.host,p.port,p.source_path,p.username,encrypted.cipher,encrypted.iv,p.ssh_fingerprint||null,p.interval_minutes).run();
    return json({id,enabled:false,message:'Source saved securely. Synchronization disabled until runner is connected.'},201);
  }
  const m=url.pathname.match(/^\/admin\/api\/sources\/([0-9a-f-]{36})$/);
  if(m && request.method==='DELETE'){
    await env.DB.prepare('DELETE FROM image_sources WHERE id=? AND enabled=0').bind(m[1]).run();
    return json({ok:true});
  }
  return denial(404);
}

function adminHtml() { return `<!doctype html><html lang="he" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Shoham Images - ניהול</title><style>body{font-family:Arial,sans-serif;background:#f4f6fa;margin:0;color:#1b2c44}header{background:#16253d;color:white;padding:18px 28px}main{max-width:1000px;margin:auto;padding:25px}section{background:white;padding:22px;border-radius:13px;margin-bottom:18px;box-shadow:0 2px 10px #172c4112}input,button{padding:12px;border-radius:8px;border:1px solid #cbd5e1}button{background:#155eef;color:white;cursor:pointer}button:disabled{opacity:.5}table{border-collapse:collapse;width:100%;text-align:right}th,td{padding:11px;border-bottom:1px solid #e2e8f0}small{color:#52627a}code{direction:ltr;display:inline-block}.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}#status{white-space:pre-wrap}</style></head><body><header><strong>Shoham Images | ניהול CDN</strong></header><main><section><h2>העלאת תמונה ידנית</h2><p><small>שם הקובץ חייב להיות דגם וקוד צבע ברצף, למשל 171204412.jpg. קבצים עם אותו מזהה יוחלפו.</small></p><form id="upload" class="row"><input type="file" id="file" accept="image/jpeg,image/png,image/webp,image/gif" required><button>העלאה</button></form><p id="status"></p></section><section><h2>חיפוש תמונה</h2><div class="row"><input id="model" placeholder="171204412" inputmode="numeric"><button id="search">חפש</button></div><p id="result"></p></section><section><h2>רשימת תמונות (למנהלים בלבד)</h2><button id="list">טען רשימה</button><p><small>הרשימה אינה זמינה בדומיין הציבורי.</small></p><div id="table"></div></section><section><h2>מקורות תמונות - FTP / SFTP</h2><p><small>פרטי התחברות נשמרים בהצפנה. מקור חדש נשאר כבוי עד לחיבור שירות הסנכרון. אין עדיין בדיקת חיבור או סנכרון.</small></p><form id="source-form"><div class="row"><label>שם מקור <input id="source-name" required maxlength="80" value="שרת תמונות ראשי"></label><label>פרוטוקול <select id="source-protocol"><option value="ftp">FTP</option><option value="sftp">SFTP</option></select></label><label>כתובת <input id="source-host" required value="185.56.74.123"></label><label>פורט <input id="source-port" type="number" min="1" max="65535" value="21" required></label><label>תיקיית מקור <input id="source-path" value="/" required></label><label>שם משתמש <input id="source-user" autocomplete="off" required></label><label>סיסמה <input id="source-pass" type="password" autocomplete="new-password" required></label><label>טביעת מפתח SSH ל-SFTP <input id="source-fingerprint" placeholder="SHA256:..."></label><label>כל כמה דקות <select id="source-interval"><option value="15">15</option><option value="5">5</option><option value="30">30</option><option value="60">60</option><option value="1440">1440</option></select></label></div><p><button type="submit">שמור מקור (כבוי)</button></p></form><p id="source-status" role="status"></p><button id="source-refresh" type="button">הצג מקורות שמורים</button><div id="source-results"></div></section></main><script>
const q=id=>document.getElementById(id);
q('upload').onsubmit=async e=>{e.preventDefault();let f=q('file').files[0]; if(!f)return; q('status').textContent='מעלה...';try{let r=await fetch('/admin/api/upload/'+encodeURIComponent(f.name),{method:'PUT',headers:{'content-type':f.type},body:f});q('status').textContent=JSON.stringify(await r.json(),null,2)}catch(e){q('status').textContent=e.message}};
q('search').onclick=()=>{const id=q('model').value.trim();q('result').textContent='';if(!/^\\d{8,18}$/.test(id)){q('result').textContent='יש להזין מזהה מספרי';return;}const a=document.createElement('a');a.href='https://cdn.kiwi-technology.com/'+id;a.target='_blank';a.rel='noopener noreferrer';a.textContent=a.href;q('result').append(a)};
q('list').onclick=async()=>{const r=await fetch('/admin/api/list?limit=100');if(!r.ok){q('table').textContent='שגיאה בטעינה';return;}const data=await r.json();const div=q('table');div.replaceChildren();const table=document.createElement('table');let tr=document.createElement('tr');for(const title of ['שם','גודל בבייטים','תאריך']){let th=document.createElement('th');th.textContent=title;tr.append(th)}table.append(tr);for(const item of data.objects){let row=document.createElement('tr');for(const val of [item.key,String(item.size),item.uploaded]){let td=document.createElement('td');td.textContent=val;row.append(td)}table.append(row)}div.append(table);if(data.truncated){let p=document.createElement('p');p.textContent='יש עוד תמונות. ניתן להשתמש בסינון prefix דרך ה-API';div.append(p)}};

q('source-protocol').onchange=()=>{q('source-port').value=q('source-protocol').value==='ftp'?'21':'22'};
q('source-form').onsubmit=async e=>{e.preventDefault();const v=id=>q(id).value.trim();const body={name:v('source-name'),protocol:v('source-protocol'),host:v('source-host'),port:Number(v('source-port')),source_path:v('source-path'),username:v('source-user'),password:q('source-pass').value,ssh_fingerprint:v('source-fingerprint'),interval_minutes:Number(v('source-interval'))};q('source-status').textContent='שומר...';try{const res=await fetch('/admin/api/sources',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});const data=await res.json();q('source-status').textContent=res.ok?'המקור נשמר בהצלחה (כבוי)':'שגיאה: '+(data.error||res.status)+(data.fields?.length?' | שדות: '+data.fields.join(', '):'');if(res.ok){q('source-pass').value='';q('source-refresh').click()}}catch(e){q('source-status').textContent='שגיאה: '+e.message}};
q('source-refresh').onclick=async()=>{const d=q('source-results');d.textContent='טוען...';try{const r=await fetch('/admin/api/sources');const j=await r.json();if(!r.ok){d.textContent=j.error||'שגיאה';return}d.replaceChildren();for(const x of j.sources){const p=document.createElement('p');p.textContent=x.name+' - '+x.protocol.toUpperCase()+' - '+x.host+':'+x.port+x.source_path+' - '+(x.enabled?'פעיל':'כבוי');d.append(p)}}catch(e){d.textContent=e.message}};
</script></body></html>`; }
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const host=url.hostname.toLowerCase();
    if (host===env.ADMIN_HOST.toLowerCase()) {
      if (!await authorized(request,env)) return denial();
      if (request.method==='GET' && url.pathname==='/') return new Response(adminHtml(),{headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','content-security-policy':"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' https://cdn.kiwi-kids.co.il; base-uri 'none'; frame-ancestors 'none'"}});
      if (url.pathname==='/admin/api/sources' || url.pathname.startsWith('/admin/api/sources/')) return sourceApi(request,env,url);
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
    if (host!==env.CDN_HOST.toLowerCase() && !host.endsWith('.shlomyb.workers.dev')) return new Response('Host not allowed',{status:404,headers:{'x-cdn-debug':'host-mismatch','cache-control':'no-store'}});
    if (!['GET','HEAD'].includes(request.method)) return new Response('Method not allowed',{status:405,headers:{allow:'GET, HEAD'}});
    if ([...url.searchParams.keys()].some(k => !['utm_source','utm_medium','utm_campaign','utm_content','utm_term'].includes(k))) return denial(404);
    const match=url.pathname.match(/^\/(\d{8,18})(?:\.(?:jpg|jpeg|png|webp|gif))?$/i);
    if (!match) return denial();
    const key=match[1];
    let object=await env.IMAGES.get(key);
    if (!object) {
      for (const ext of ['jpg','jpeg','png','webp','gif']) {
        object=await env.IMAGES.get(`${key}.${ext}`);
        if (object) break;
      }
    }
    if (!object) return new Response('Image not found in R2',{status:404,headers:{'cache-control':'no-store','x-cdn-debug':'r2-object-missing'}});
    const headers=new Headers(); object.writeHttpMetadata(headers);
    if (!ALLOWED.has(headers.get('content-type'))) return denial(404);
    headers.set('etag',object.httpEtag);
    headers.set('cache-control','public, max-age=300, s-maxage=300');
    headers.set('x-content-type-options','nosniff');
    headers.set('content-security-policy',"default-src 'none'; sandbox");
    return new Response(request.method==='HEAD'?null:object.body,{status:200,headers});
  }
};
