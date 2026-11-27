// ============================================================
// K36 บอทหลังบ้าน — Railway worker v0.1
// ตอนนี้ทำอย่างเดียว: ล็อกอินทุกเว็บที่ตั้งบัญชีไว้ใน K36 แล้วรายงานสถานะกลับ
//
// Variables ที่ต้องตั้งใน Railway:
//   SUPABASE_URL     = https://xxxx.supabase.co
//   SUPABASE_KEY     = คีย์ Supabase (ตัวเดียวกับที่ K36 ใช้)
//   BO_PRIVATE_KEY   = กุญแจลับที่ได้ตอนกด "สร้างกุญแจ" ใน K36
// ============================================================
const crypto = require('node:crypto');
const http = require('node:http');
const { ProxyAgent } = require('undici');

const SB_URL = String(process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const SB_KEY = process.env.SUPABASE_KEY || '';
// อ่านกุญแจลับ: จากไฟล์ก่อน (เลี่ยงปัญหา systemd ตัด \n ของค่ายาว) แล้วค่อย fallback เป็น env
const PRIV_PEM = (function () {
  const fsx = require('fs'), px = require('path');
  const f = process.env.BO_PRIVATE_KEY_FILE || px.join(__dirname, 'bo_key.pem');
  try { if (fsx.existsSync(f)) { const t = fsx.readFileSync(f, 'utf8').trim(); if (t) return t; } } catch (e) {}
  return String(process.env.BO_PRIVATE_KEY || '').replace(/\\n/g, '\n').trim();
})();
const PROXY_URL = String(process.env.PROXY_URL || '').trim(); // เช่น socks5h://127.0.0.1:1080

const LOOP_MS = 2 * 1000;        // เช็กคิวงานทุก 2 วินาที
const RELOGIN_BEFORE_MS = 20 * 60 * 1000;  // ล็อกอินใหม่ก่อน token หมด 20 นาที
const FAIL_COOLDOWN_MS = 15 * 60 * 1000;   // ล็อกอินพลาด → รอ 15 นาทีก่อนลองรหัสเดิมซ้ำ (กันบัญชีโดนล็อก)
const HTTP_TIMEOUT_MS = 20 * 1000;
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';

const proxyAgent = PROXY_URL ? new ProxyAgent(PROXY_URL) : undefined;
const boFetchOpts = () => proxyAgent ? { dispatcher: proxyAgent } : {};

const sessions = new Map(); // siteId -> { token, exp, cipher, failedAt, failedCipher }
const fastSiteCache = new Map(); // siteId -> site object (ให้วงจรเร็วใช้)

const log = (...a) => console.log(new Date().toISOString(), ...a);

// ---------- เช็กค่าเริ่มต้น ----------
function fatal(msg) {
  console.error('❌ ' + msg);
  process.exit(1);
}
if (!SB_URL) fatal('ไม่ได้ตั้ง SUPABASE_URL');
if (!SB_KEY) fatal('ไม่ได้ตั้ง SUPABASE_KEY');
if (!PRIV_PEM.includes('PRIVATE KEY')) fatal('ไม่ได้ตั้ง BO_PRIVATE_KEY หรือวางไม่ครบ');

let privateKey, KEY_FP;
try {
  privateKey = crypto.createPrivateKey(PRIV_PEM);
  const spki = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  KEY_FP = crypto.createHash('sha256').update(spki).digest('hex').slice(0, 16).toUpperCase().match(/.{4}/g).join('-');
} catch (e) {
  fatal('BO_PRIVATE_KEY ใช้ไม่ได้: ' + e.message);
}
log('🔑 ลายนิ้วมือกุญแจ:', KEY_FP, '(ต้องตรงกับที่แสดงในหน้า K36)');

// ---------- Supabase REST ----------
async function sb(method, path, body, prefer) {
  const res = await fetch(SB_URL + '/rest/v1/' + path, {
    method,
    headers: {
      apikey: SB_KEY,
      Authorization: 'Bearer ' + SB_KEY,
      'Content-Type': 'application/json',
      Prefer: prefer || 'return=minimal'
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS)
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Supabase ${res.status}: ${text.slice(0, 200)}`);
  return text ? JSON.parse(text) : null;
}

const patchSite = (id, data) => sb('PATCH', `bo_sites?id=eq.${encodeURIComponent(id)}`, data)
  .catch(e => log('⚠️ อัปเดตสถานะ', id, 'ไม่สำเร็จ:', e.message));

// ---------- ไขรหัส ----------
function decryptCred(site) {
  if (site.cipher_fp && site.cipher_fp !== KEY_FP) {
    throw new Error('บัญชีถูกล็อกด้วยกุญแจคนละชุดกับที่ใส่ใน Railway — ตั้งบัญชีใหม่ใน K36 หรือใส่ BO_PRIVATE_KEY ให้ตรง');
  }
  let obj;
  try {
    const plain = crypto.privateDecrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      Buffer.from(site.cred_cipher, 'base64')
    );
    obj = JSON.parse(plain.toString('utf8'));
  } catch (e) {
    throw new Error('ไขรหัสบัญชีไม่ได้ — กุญแจไม่ตรง ตั้งบัญชีใหม่ใน K36');
  }
  if (obj.s !== site.id) throw new Error('บัญชีนี้ถูกตั้งไว้ให้เว็บอื่น — ตั้งบัญชีใหม่ใน K36');
  if (!obj.u || !obj.p) throw new Error('บัญชีไม่ครบ');
  return { userid: obj.u, password: obj.p, totp: obj.g || '' };   // g = รหัสลับ Google Authenticator (หลังบ้าน TCG)
}

// หน้าเว็บส่งรหัสเป็น SHA-1 (ตัวอักษร 40 ตัว) — ถ้าใส่มาเป็นแบบนั้นอยู่แล้วก็ใช้ตรง ๆ
function hashPassword(p) {
  // ถ้าใส่ค่าที่ hash มาแล้ว (40 ตัว hex) ให้ส่งตรง ๆ — ใช้กับหลังบ้านที่มีสูตรเข้ารหัสเฉพาะ
  if (/^[0-9a-f]{40}$/i.test(p)) return p.toLowerCase();
  // ไม่งั้น hash แบบ sha1 มาตรฐาน
  return crypto.createHash('sha1').update(p, 'utf8').digest('hex');
}

function jwtExp(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    return payload.exp ? payload.exp * 1000 : Date.now() + 60 * 60 * 1000;
  } catch (e) {
    return Date.now() + 60 * 60 * 1000;
  }
}

// สรุปหน้า HTML ที่ตอบกลับมา (หน้า error/บล็อก) ให้อ่านง่ายในบรรทัดเดียว
function htmlSummary(text) {
  if (!text || !/^\s*</.test(text)) return (text || '').slice(0, 150);
  const title = (text.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || '';
  const body = text.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
  return ('หน้าเว็บ: ' + (title.trim() || '-') + ' | ' + body.slice(0, 200)).trim();
}

function boHeaders(site, token) {
  const origin = new URL(site.web_url).origin;
  const h = {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/plain, */*',
    Origin: origin,
    Referer: origin + '/',
    'User-Agent': UA
  };
  if (token) h.Authorization = token; // หลังบ้านนี้ส่ง token ตรง ๆ ไม่มีคำว่า Bearer
  h['x-currency'] = 'THB';   // บางปลายทาง (เช่น widdepinfo ของหน้าปรับยอด) ต้องมี header นี้
  return h;
}

// ---------- ล็อกอิน ----------
const isTcg = site => String(site.platform || '').toLowerCase() === 'tcg';
async function login(site, cred) {
  if (isTcg(site)) return tcgLogin(site, cred);
  return k36Login(site, cred);
}
async function k36Login(site, cred) {
  const res = await fetch(site.api_base + '/login', {
    method: 'POST',
    headers: boHeaders(site),
    body: JSON.stringify({ userid: cred.userid, password: hashPassword(cred.password) }),
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
    ...boFetchOpts()
  });
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch (e) {}

  if (!res.ok) {
    const why = (data && (data.message || data.error || data.msg)) || htmlSummary(text) || ('HTTP ' + res.status);
    log('🔎', site.id, 'login ตอบกลับ', res.status, 'server=' + (res.headers.get('server') || '-'),
      'cf-ray=' + (res.headers.get('cf-ray') || '-'), 'type=' + (res.headers.get('content-type') || '-'));
    if (res.status === 403) throw new Error('หลังบ้านไม่ให้เข้า (403) — อาจจำกัด IP ต้องให้ทีมหลังบ้านเพิ่ม IP ของ Railway: ' + why);
    throw new Error(`ล็อกอินไม่ผ่าน (${res.status}): ${why}`);
  }
  if (!data || !data.token) throw new Error('ล็อกอินแล้วไม่ได้ token กลับมา');
  if (data.verifytype && data.verifytype !== 'none') throw new Error('หลังบ้านขอยืนยันตัวตนเพิ่ม (' + data.verifytype + ') บอทล็อกอินเองไม่ได้');
  return { token: data.token, exp: jwtExp(data.token) };
}

async function handleSite(site) {
  fastSiteCache.set(site.id, site); // ให้วงจรเร็วใช้ข้อมูล site นี้
  if (siteBusy.has(site.id)) return; // วงจรเร็วกำลังทำงานของเว็บนี้อยู่ — ไม่ล็อกอินซ้อน (กัน token เดิมถูกตัดกลางงาน)
  const now = Date.now();
  let s = sessions.get(site.id) || {};

  if (!site.cred_cipher) {
    sessions.delete(site.id);
    return;
  }

  const credChanged = s.cipher !== site.cred_cipher;
  const needLogin = credChanged || !s.token || s.exp - now < RELOGIN_BEFORE_MS;

  if (needLogin) {
    // ล็อกอินพลาดด้วยรหัสเดิม → รอก่อน ไม่ลองรัว ๆ
    if (!credChanged && s.failedCipher === site.cred_cipher && now - s.failedAt < FAIL_COOLDOWN_MS) return;

    let cred;
    try {
      cred = decryptCred(site);
    } catch (e) {
      sessions.set(site.id, { cipher: site.cred_cipher, failedAt: now, failedCipher: site.cred_cipher });
      log('🔒', site.id, e.message);
      return patchSite(site.id, { status: 'error', last_error: e.message, last_seen: new Date().toISOString() });
    }

    try {
      const r = await login(site, cred);
      s = { token: r.token, exp: r.exp, cipher: site.cred_cipher, extra: r.extra };
      sessions.set(site.id, s);
      log('✅', site.id, 'ล็อกอินสำเร็จ token หมดอายุ', new Date(r.exp).toISOString());
      await patchSite(site.id, {
        status: 'ok', last_error: null,
        last_login_at: new Date().toISOString(), last_seen: new Date().toISOString()
      });
      await processTasks(site, s.token).catch(e => log('⚠️ งานค้าง', site.id, e.message));
      return;
    } catch (e) {
      const msg = e.name === 'TimeoutError' ? 'ติดต่อหลังบ้านไม่ได้ (หมดเวลา)' : e.message;
      sessions.set(site.id, { cipher: site.cred_cipher, failedAt: now, failedCipher: site.cred_cipher });
      log('❌', site.id, msg);
      return patchSite(site.id, { status: 'login_failed', last_error: msg, last_seen: new Date().toISOString() });
    }
  }

  // ยังล็อกอินอยู่ → ส่งสัญญาณชีพ + ทำงานในคิว
  await patchSite(site.id, { status: 'ok', last_seen: new Date().toISOString() });
  await processTasks(site, s.token).catch(e => log('⚠️ งานค้าง', site.id, e.message));
}

// ---------- ดึง token ที่ใช้ได้ (ล็อกอินให้ถ้ายังไม่มี) ----------
async function ensureToken(site) {
  let s = sessions.get(site.id) || {};
  const now = Date.now();
  if (s.token && s.cipher === site.cred_cipher && s.exp - now > 60 * 1000) return s.token;
  const cred = decryptCred(site);
  const r = await login(site, cred);
  s = { token: r.token, exp: r.exp, cipher: site.cred_cipher, extra: r.extra };
  sessions.set(site.id, s);
  return r.token;
}

// สถานะที่ถือว่า "token มีปัญหา" → ล้าง session แล้วล็อกอินใหม่
// (ไม่รวม 499: 499 ของหลังบ้านนี้คือ UNHANDLED_EXCEPTION ฝั่งเซิร์ฟเวอร์ ไม่ใช่ token)
const AUTH_FAIL_STATUS = [ 401, 403, 498 ];
// สกุลที่ลองดึง (ช่องส่วนใหญ่เป็น THB บางช่องเป็น USDT)
const CURRENCIES = [ 'THB', 'USDT' ];

// ---------- เรียก API หลังบ้าน (ผ่าน proxy + ใส่ token) ----------
// ถ้าเจอ token หมดอายุ/ถูกตัด (401/403/498) จะล็อกอินใหม่แล้วลองซ้ำอัตโนมัติ 1 ครั้ง (499 ไม่ใช่ token — จัดการแยกที่ get/save)
async function boApi(site, token, method, path, body, _retried) {
  const url = site.api_base + path;
  const res = await fetch(url, {
    method,
    headers: boHeaders(site, token),
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
    ...boFetchOpts()
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) {}
  const authFail = AUTH_FAIL_STATUS.includes(res.status);
  if (authFail) sessions.delete(site.id);   // token มีปัญหา → ล้างให้ล็อกอินใหม่
  if (!res.ok) {
    log('🔻 boApi', site.id, method, path, '→', res.status,
        'ct=' + (res.headers.get('content-type') || '-'),
        'server=' + (res.headers.get('server') || '-'),
        'body=' + (text || '').slice(0, 220).replace(/\s+/g, ' '));
    // ล็อกอินใหม่แล้วลองซ้ำครั้งเดียว (กัน token หมดอายุ/การเชื่อมต่อถูกตัดชั่วคราว)
    if (authFail && !_retried) {
      try {
        const fresh = await ensureToken(site);
        return await boApi(site, fresh, method, path, body, true);
      } catch (e2) { /* ล็อกอินใหม่ไม่ผ่าน → ตกไปโยน error ด้านล่าง */ }
    }
    let why = (data && (data.message || data.error || data.msg)) || ('HTTP ' + res.status);
    if (res.status === 499 || /UNHANDLED_EXCEPTION/i.test(text || '')) {
      why = 'หลังบ้านดึงช่องทางนี้ไม่ได้ (error ' + res.status + ') — ช่องทางนี้อาจไม่มีข้อมูลสกุล THB หรือข้อมูลฝั่งหลังบ้านผิดปกติ';
    }
    const e = new Error(why); e.httpStatus = res.status; throw e;
  }
  return data;
}

// POST แบบ multipart/form-data (ใช้กับฝากมือเข้ายูส /deposits/thirdParty) + ล็อกอินใหม่ลองซ้ำ 1 ครั้งถ้า token มีปัญหา
async function boApiForm(site, token, path, fields, _retried) {
  const url = site.api_base + path;
  const origin = new URL(site.web_url).origin;
  const fd = new FormData();
  for (const [k, v] of Object.entries(fields)) fd.append(k, v == null ? '' : String(v));
  const headers = { Accept: 'application/json, text/plain, */*', Origin: origin, Referer: origin + '/', 'User-Agent': UA, 'x-currency': 'THB' };
  if (token) headers.Authorization = token;
  const res = await fetch(url, { method: 'POST', headers, body: fd, signal: AbortSignal.timeout(HTTP_TIMEOUT_MS), ...boFetchOpts() });
  const text = await res.text();
  let data = null; try { data = text ? JSON.parse(text) : null; } catch (e) {}
  const authFail = AUTH_FAIL_STATUS.includes(res.status);
  if (authFail) sessions.delete(site.id);
  if (!res.ok) {
    log('🔻 boApiForm', site.id, 'POST', path, '→', res.status, 'body=' + (text || '').slice(0, 220).replace(/\s+/g, ' '));
    if (authFail && !_retried) {
      try { const fresh = await ensureToken(site); return await boApiForm(site, fresh, path, fields, true); } catch (e2) {}
    }
    const why = (data && (data.message || data.error || data.msg)) || ('HTTP ' + res.status);
    const e = new Error(why); e.httpStatus = res.status; throw e;
  }
  return data;
}

function _dstr(ms) { const d = new Date(ms), p = n => String(n).padStart(2, '0'); return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()); }

// หาเลขออร์เดอร์หลังบ้าน (เช่น TF6N883OK28166...) — เอาเฉพาะ "โทเคน" ที่มีรหัสช่อง+ตัวเลข ตัดส่วนอื่น (เช่น " / BT678") ทิ้ง
function findOrderNo(obj, code) {
  let found = null;
  const pick = str => {
    const toks = String(str).split(/[\s\/|,;]+/);
    for (const t of toks) { if (code && t.indexOf(code) >= 0 && /\d{6,}/.test(t)) return t; }
    return null;
  };
  const walk = o => {
    if (found || o == null) return;
    if (typeof o === 'string') { const t = pick(o); if (t) found = t; return; }
    if (typeof o === 'object') { for (const k in o) { if (found) break; walk(o[k]); } }
  };
  walk(obj); return found;
}

// เขียนลงชีตผ่าน Google Apps Script webhook (ไม่ให้พังการฝากถ้าชีตมีปัญหา)
async function writeSheet(p, dep) {
  const url = process.env.SHEET_WEBHOOK_URL, secret = process.env.SHEET_WEBHOOK_SECRET || '';
  if (!url) { log('🧾 sheet: ไม่ได้ตั้ง SHEET_WEBHOOK_URL'); return null; }
  if (!p.sheet) { log('🧾 sheet: ไม่มีข้อมูลชีตจากเว็บ (p.sheet ว่าง — เว็บอาจเป็นเวอร์ชันเก่า)'); return null; }
  const s = p.sheet;
  // ส่งเป็น query param (Apps Script อ่านจาก e.parameter ได้ชัวร์ — ไม่โดนตัดตอน redirect เหมือน body)
  const qs = new URLSearchParams({
    secret, web: s.web || '', date: s.date || '',
    account: s.account || '', orderBO: dep.orderBO || '', user: p.playerid || '',
    sheetAmt: (s.sheetAmt == null ? '' : String(s.sheetAmt)), amount: String(dep.amount || 0),
    staff: s.staff || '', noteBD: p.orderno || ''
  }).toString();
  const base = url + (url.indexOf('?') >= 0 ? '&' : '?') + qs;
  // Apps Script คืนหน้า interstitial (HTML) แบบสุ่มเวลายิงจากเซิร์ฟเวอร์ → ลองซ้ำได้ถึง 4 ครั้ง
  let j = null, lastStatus = 0, lastTxt = '';
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      const full = base + '&_r=' + Date.now() + attempt;   // กัน cache
      const res = await fetch(full, { method: 'GET', headers: { 'User-Agent': UA, 'Accept': 'application/json, text/plain, */*' }, signal: AbortSignal.timeout(15000), redirect: 'follow' });
      lastStatus = res.status; lastTxt = await res.text();
      try { j = JSON.parse(lastTxt); } catch (e) { j = null; }
    } catch (e) { lastTxt = 'fetch error: ' + (e.message || e); j = null; }
    if (j) { if (attempt > 1) log('🧾 sheet', s.web, 'สำเร็จหลังลองซ้ำครั้งที่', attempt); break; }
    if (attempt < 4) await _sleep(700 * attempt);   // รอแล้วลองใหม่
  }
  log('🧾 sheet', s.web, s.date, '→ HTTP', lastStatus, '·', (lastTxt || '').slice(0, 120).replace(/\s+/g, ' '));
  if (!j) return { ok: false, error: 'webhook ไม่ตอบ JSON หลังลองซ้ำ 4 ครั้ง (Apps Script เด้งหน้า login ชั่วคราว — ลองฝากใหม่อีกครั้ง)' };
  return j;
}

// อ่านสรุปจากชีต: ให้วันที่ → Apps Script อ่านแท็บ "บุคคลที่3" + "ปรับด้วยมือ" ของทุกไฟล์วันนั้น → คืนแถวดิบ
const _sheetSumCache = new Map();   // date -> { at, data }  (แคชสั้นๆ กันอ่าน Google ซ้ำถี่ๆ)
const SHEET_SUM_TTL = 25000;
async function readSheet(date) {
  const key = String(date || '');
  const cached = _sheetSumCache.get(key);
  if (cached && Date.now() - cached.at < SHEET_SUM_TTL) return cached.data;
  const url = process.env.SHEET_WEBHOOK_URL, secret = process.env.SHEET_WEBHOOK_SECRET || '';
  if (!url) throw new Error('ยังไม่ได้ตั้ง SHEET_WEBHOOK_URL ที่บอท');
  const qs = new URLSearchParams({ secret, summary: '1', date: String(date || '') }).toString();
  const base = url + (url.indexOf('?') >= 0 ? '&' : '?') + qs;
  let j = null, lastTxt = '';
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      const res = await fetch(base + '&_r=' + Date.now() + attempt, { method: 'GET', headers: { 'User-Agent': UA, 'Accept': 'application/json, text/plain, */*' }, signal: AbortSignal.timeout(180000), redirect: 'follow' });
      lastTxt = await res.text();
      try { j = JSON.parse(lastTxt); } catch (e) { j = null; }
    } catch (e) { lastTxt = 'fetch error: ' + (e.message || e); j = null; }
    if (j) break;
    if (attempt < 4) await _sleep(800 * attempt);
  }
  log('🧾 sheet-summary', date, '→', (lastTxt || '').slice(0, 120).replace(/\s+/g, ' '));
  if (!j) throw new Error('ชีตไม่ตอบ JSON (Apps Script อาจเด้ง login ชั่วคราว — ลองใหม่อีกครั้ง)');
  if (!j.ok) throw new Error(j.error || 'อ่านชีตไม่สำเร็จ');
  _sheetSumCache.set(key, { at: Date.now(), data: j });
  // เก็บลง Supabase (settings) ให้หน้า FT อ่านได้ทันที ไม่ต้องรอ Google
  putSetting('ft_sheetsum_' + key, { rows: j.rows || [], count: j.count || 0, at: Date.now() }).catch(() => {});
  return j;   // { ok, date, count, rows:[{web,source,staff,user,amount,orderBO,account}] }
}
// อุ่นแคชชีตไว้ล่วงหน้าใน Supabase → หน้า FT อ่านเด้งทันที
// วันนี้+เมื่อวาน: อัปเดตทุกรอบ (เปลี่ยนตลอด) · วันเก่า: ไล่เก็บทีละวันจนครบ แล้วข้าม (นิ่งแล้วไม่อ่านซ้ำ)
const SHEET_BACKFILL_DAYS = 60;   // เก็บย้อนหลังสูงสุดกี่วัน
function _dateMinus(ds, n) { const d = new Date(ds + 'T00:00:00Z'); d.setUTCDate(d.getUTCDate() - n); return d.toISOString().slice(0, 10); }
let _warmBusy = false, _warmScan = 2;
async function sheetWarmLoop() {
  if (!process.env.SHEET_WEBHOOK_URL || _warmBusy) return;   // กันรอบชนกัน (วันเต็มอ่านนาน)
  _warmBusy = true;
  try {
    const today = bangkokNow().date;
    try { await readSheet(today); } catch (e) { log('⚠️ อุ่นชีตวันนี้', e.message || e); }
    try { await readSheet(_dateMinus(today, 1)); } catch (e) {}   // เมื่อวาน (อาจมีแก้)
    // ไล่หา "วันเก่าที่ยังไม่มีใน Supabase" แล้วเก็บทีละ 1 วันต่อรอบ (วันเก่าเก็บครั้งเดียวพอ)
    for (let k = 0; k < SHEET_BACKFILL_DAYS; k++) {
      const i = 2 + ((_warmScan - 2 + k) % SHEET_BACKFILL_DAYS);
      const d = _dateMinus(today, i);
      let have = null; try { have = await getSetting('ft_sheetsum_' + d); } catch (e) {}
      if (!have || !have.rows) {                  // ยังไม่มี → อ่านมาเก็บ แล้วหยุด (เหลือรอบหน้าค่อยเก็บวันถัดไป)
        try { await readSheet(d); log('🧾 อุ่นย้อนหลังเก็บแล้ว', d); } catch (e) { log('⚠️ อุ่นย้อนหลัง', d, e.message || e); }
        _warmScan = i + 1; break;
      }
    }
  } finally { _warmBusy = false; }
}

// ========================================================
// ความสามารถของ "ระบบหลังบ้านแบบ K36 (tf6prod-ims)"
// งานช่องทางชำระเงิน: list / get / save
// ========================================================
const VALID_PAYTYPES = ['QR_BANK', 'PROMPTPAY', 'TRUEMONEY', 'DEBIT_CARD', 'USDT'];

// ดึงค่าดิบของช่องทาง: ลอง THB ก่อน ถ้าพังแบบ 499/UNHANDLED (ชั่วคราว) รอแล้วลองสกุลเดิมซ้ำ 1 ครั้ง
// แล้วค่อยลอง USDT ให้; error อื่น (เช่น token) โยนทันที ไม่ไล่สกุลต่อ  — ใช้ร่วมทั้ง get/save (กันเขียนซ้ำ)
// จำว่าช่องไหนดึงได้ด้วยสกุลอะไร (เช่นช่อง USDT) → รอบหน้าขอสกุลนั้นก่อนเลย
// ไม่ต้องยิง /THB ให้หลังบ้านตอบ 499 ซ้ำทุก 2.5 นาที (เดิม ~288 บรรทัด error/ชม.)
const chanCurrency = new Map();   // "siteId|channelId" -> 'THB' | 'USDT'
async function getRawChannel(site, token, channelId) {
  const cid = encodeURIComponent(channelId);
  const memoKey = site.id + '|' + channelId;
  const known = chanCurrency.get(memoKey);
  const order = known ? [known].concat(CURRENCIES.filter(c => c !== known)) : CURRENCIES;
  let raw, lastErr;
  for (const c of order) {
    let got = false;
    for (let attempt = 0; attempt < 2 && !got; attempt++) {
      try { raw = await boApi(site, token, 'GET', `/thirdpartypayments/${cid}/${c}`); lastErr = null; got = true; }
      catch (e) {
        lastErr = e;
        const retriable = (e.httpStatus === 499 || /UNHANDLED_EXCEPTION/i.test(e.message || ''));
        if (!retriable) throw e;
        if (attempt === 0) await new Promise(r => setTimeout(r, 400));
      }
    }
    if (got) { chanCurrency.set(memoKey, c); break; }
  }
  if (raw === undefined) { chanCurrency.delete(memoKey); throw lastErr; }
  return raw;
}

const K36 = {
  // ดึงข้อมูลยูส (สำหรับหน้าปรับยอด) — read-only
  async playerInfo(site, token, playerid) {
    // หลังบ้าน widdepinfo ค้นแบบตรงเป๊ะ (สนตัวเล็ก/ใหญ่) — ลองหลายรูปแบบ: ตามพิมพ์ → ตัวเล็กหมด → ตัวใหญ่หมด
    const typed = String(playerid).trim();
    const variants = [...new Set([typed, typed.toLowerCase(), typed.toUpperCase()])];
    let d = null;
    for (const v of variants) {
      try {
        const r = await boApi(site, token, 'GET', `/players/${encodeURIComponent(v)}/widdepinfo?accounttype=1&language=5`);
        if (r && r.playerid) { d = r; break; }
      } catch (_) { /* รูปแบบนี้ไม่เจอ ลองตัวถัดไป */ }
    }
    if (!d || !d.playerid) throw new Error('ไม่พบรหัสสมาชิกนี้');
    const pick = m => Number((m && (m.THB != null ? m.THB : 0)) || 0);
    return {
      playerid: d.playerid,
      name: d.firstname || '',
      mobile: d.mobile || '',
      currency: d.currency || 'THB',
      available: Number(d.availablebalance || 0),
      total: Number(d.totalbalance || 0),
      pending: Number(d.pendingbalance || 0),
      minDeposit: pick(d.minDepositAmtMap),
      maxDeposit: pick(d.maxDepositAmtMap),
      avgDeposit: Number(d.playeravgdepositamt || 0),
      lastDeposit: d.lastdeposittime || null,
      lastWithdraw: d.lastwithdrawtime || null,
      banks: Array.isArray(d.playerbankinfo) ? d.playerbankinfo.map(b => ({ bankname: b.bankname || '', paymentid: b.paymentid || '' })) : []
    };
  },

  // ฝากมือเข้ายูส (เงินฝากผ่านบุคคลที่สาม) — ฝากเข้าตรง status=2
  async deposit(site, token, p) {
    const amt = Number(p.amount);
    if (!p.playerid) throw new Error('ไม่ได้ระบุรหัสสมาชิก');
    if (!(amt > 0)) throw new Error('จำนวนเงินไม่ถูกต้อง');
    if (!p.channelid || !p.channelcode) throw new Error('ไม่ได้เลือกบัญชี/บุคคลที่สาม');
    if (!p.paytype) throw new Error('ไม่ได้เลือกประเภทการชำระเงิน');
    if (!p.bankcode) throw new Error('ไม่ได้เลือกช่องทางการชำระเงิน');
    if (!p.orderno) throw new Error('ไม่ได้ใส่หมายเลขออร์เดอร์');
    const fields = {
      playerid: String(p.playerid).trim(),
      depositamt: amt,
      thirdPartyRemoteOrderNo: String(p.orderno).trim(),
      remarks: p.remarks || '',
      thirdpartypaymentbankcode: p.bankcode,
      depositPaymentTypeEnum: p.paytype,
      thirdpartypaymentcode: p.channelcode,
      thirdpartypaymentid: p.channelid,
      currency: 'THB',
      status: 2,                 // ฝากเข้าตรง (ข้ามขั้นตอนตรวจสอบ)
      requesttime: Date.now()
    };
    let d;
    try {
      d = await boApiForm(site, token, '/deposits/thirdParty', fields);
    } catch (e) {
      // พิมพ์ตัวเล็ก/ใหญ่ไม่ตรงกับที่หลังบ้านเก็บ → หา player ไม่เจอ: ค้นชื่อจริง (หลังบ้านค้นแบบไม่สนเคส) แล้วฝากใหม่ครั้งเดียว
      if (/player\s*not\s*found|user\s*not\s*found|ไม่พบ(รหัส|ผู้เล่น|ยูส)/i.test(e.message || '')) {
        let real = '';
        try { const info = await this.playerInfo(site, token, fields.playerid); real = info && info.playerid ? String(info.playerid).trim() : ''; } catch (_) {}
        if (real && real !== fields.playerid) {
          log('🔤 แก้ตัวพิมพ์ยูส', site.id, fields.playerid, '→', real, '(ฝากใหม่อัตโนมัติ)');
          fields.playerid = real;
          d = await boApiForm(site, token, '/deposits/thirdParty', fields);
        } else { throw e; }
      } else { throw e; }
    }
    return { ok: true, playerid: fields.playerid, amount: amt, orderno: fields.thirdPartyRemoteOrderNo, orderBO: findOrderNo(d, p.channelcode) || '', result: d || null };
  },

  // ดึงเลขออร์เดอร์หลังบ้าน (TF6N883OK...) จากรายการเงินฝากล่าสุดของยูส (หลัง deposit)
  async fetchOrderBO(site, token, playerid, channelcode, bdOrder) {
    const now = Date.now();
    const body = {
      exactMatch: true, zoneType: 'ASIA_HO_CHI_MINH', dateTo: _dstr(now), dateFrom: _dstr(now - 86400000),
      timeFilter: 'deposittime', sortColumn: 'deposittime', sort: 'DESC', limit: 50, offset: 0,
      statusType: 'DEPOSIT_RECORD', language: 5, playerId: playerid, startTime: now - 2 * 86400000, endTime: now + 3600000
    };
    const res = await boApi(site, token, 'POST', '/deposits/search', body);
    let rows = Array.isArray(res) ? res : (res && (res.data || res.records || res.list || res.content || res.rows)) || [];
    if (!Array.isArray(rows)) rows = [];
    let rec = null;
    if (bdOrder) rec = rows.find(r => { try { return JSON.stringify(r).indexOf(bdOrder) >= 0; } catch (e) { return false; } });
    if (!rec) rec = rows[0];
    return rec ? (findOrderNo(rec, channelcode) || '') : '';
  },

  // ตรวจว่า BD ออร์เดอร์นี้ "เข้าหลังบ้านจริงหรือยัง" — ใช้กู้สถานะตอน HTTP timeout (เข้าแล้วแต่ตอบไม่ทัน)
  // คืน record ถ้าเจอ (ฝากเข้าแล้ว) / null ถ้ายังไม่พบ (ยังไม่เข้า)
  async findDeposit(site, token, playerid, bdOrder) {
    if (!bdOrder) return null;
    const now = Date.now();
    const body = {
      exactMatch: true, zoneType: 'ASIA_HO_CHI_MINH', dateTo: _dstr(now), dateFrom: _dstr(now - 86400000),
      timeFilter: 'deposittime', sortColumn: 'deposittime', sort: 'DESC', limit: 50, offset: 0,
      statusType: 'DEPOSIT_RECORD', language: 5, playerId: playerid, startTime: now - 2 * 86400000, endTime: now + 3600000
    };
    const res = await boApi(site, token, 'POST', '/deposits/search', body);
    let rows = Array.isArray(res) ? res : (res && (res.data || res.records || res.list || res.content || res.rows)) || [];
    if (!Array.isArray(rows)) rows = [];
    const bd = String(bdOrder).trim();
    return rows.find(r => { try { return JSON.stringify(r).indexOf(bd) >= 0; } catch (e) { return false; } }) || null;
  },

  // ดึงข้อมูลสำหรับ 3 dropdown ของฟอร์มฝาก: ประเภทที่เปิด + แบงก์ของแต่ละประเภท
  async depositForm(site, token, channelId) {
    if (!channelId) throw new Error('ไม่ได้ระบุช่องทาง/บัญชี');
    const ch = await this.getChannel(site, token, channelId);
    const tset = (ch.values && ch.values.types) || {};
    const codes = Object.keys(tset).filter(c => tset[c].enabled);
    const types = [];
    for (const code of codes) {
      let banks = [];
      try {
        const b = await boApi(site, token, 'GET', `/thirdpartypaymentbanks?thirdpartypaymentid=${encodeURIComponent(channelId)}&depositPaymentTypeEnum=${encodeURIComponent(code)}&currency=THB`);
        const bname = x => {
          const n = x.bankname;
          if (typeof n === 'string' && n) return n;
          if (n && typeof n === 'object') return n['th-TH'] || n['en-US'] || Object.values(n).find(v => typeof v === 'string') || '';
          return (typeof x.displayname === 'string' && x.displayname) || (typeof x.name === 'string' && x.name) || x.bankaccountname || x.thirdpartypaymentbankname || '';
        };
        banks = (Array.isArray(b) ? b : []).filter(x => x && x.isenabled !== false).map(x => ({ code: x.thirdpartypaymentbankcode, name: bname(x) || x.thirdpartypaymentbankcode }));
      } catch (e) { /* ประเภทที่อ่านแบงก์ไม่ได้ ปล่อยว่าง */ }
      types.push({ code, banks });
    }
    return { channelid: ch.id, channelcode: ch.code, name: ch.name, types };
  },

  // ดึงรายชื่อช่องทางทั้งหมด
  async listChannels(site, token) {
    const rows = await boApi(site, token, 'GET', '/thirdpartypayments?currency=THB');
    const arr = Array.isArray(rows) ? rows : (rows && rows.data) || [];
    return arr.map(x => ({
      id: x.thirdpartypaymentid,
      code: x.thirdpartypaymentcode,
      name: (x.thirdpartypaymentdisplayname && (x.thirdpartypaymentdisplayname['th-TH'] || x.thirdpartypaymentdisplayname['en-US'])) || x.thirdpartypaymentstaticname || x.thirdpartypaymentcode,
      staticname: x.thirdpartypaymentstaticname || ''
    }));
  },

  // ดึงค่าปัจจุบันของช่องทาง (ค่าดิบ + ค่าที่แก้ได้แบบย่อ)
  // บางช่องเป็นสกุล USDT ไม่ใช่ THB → ขอ /THB ก่อน ถ้าพัง (499/UNHANDLED) ลอง /USDT
  async getChannel(site, token, channelId) {
    const raw = await getRawChannel(site, token, channelId);
    const cur = (raw.currencies && (raw.currencies.find(c => c.currency === 'THB') || raw.currencies[0])) || {};
    const pts = cur.paymenttypesetting || {};
    const ptcs = cur.paymentTypeChannelStatuses || {};
    const inList = Array.isArray(cur.depositPaymentTypes) ? cur.depositPaymentTypes : Object.keys(pts);
    // สถานะเปิด/ปิดประเภท = อ่าน "แบงก์จริง ต่อประเภท" แบบเดียวกับตอนกดเปิด/ปิดเป๊ะ (depositPaymentTypeEnum)
    // → snapshot ตรงกับความจริงเสมอ ไม่เด้งกลับเป็นเปิดหลังรีหน้า · อ่านประเภทไหนไม่ได้ค่อย fallback เฉพาะอันนั้น
    const codes = Object.keys(pts);
    const bankOn = {};
    await Promise.all(codes.map(async code => {
      try {
        const banks = await boApi(site, token, 'GET', `/thirdpartypaymentbanks?thirdpartypaymentid=${encodeURIComponent(channelId)}&depositPaymentTypeEnum=${encodeURIComponent(code)}&currency=THB`);
        if (Array.isArray(banks) && banks.length) bankOn[code] = banks.some(b => b && b.isenabled);   // มีแบงก์เปิดอยู่ = ประเภทเปิด
      } catch (e) { /* อ่านไม่ได้ → ปล่อยให้ fallback */ }
    }));
    const typeEnabled = code => {
      if (bankOn[code] !== undefined) return bankOn[code];   // มีแบงก์จริงของประเภทนี้ → ใช้ค่าจากแบงก์ (แม่นสุด)
      const a = ptcs[code]; return (Array.isArray(a) && a.length) ? a.some(x => x && x.enabled) : inList.includes(code);
    };
    const types = {};
    for (const code of Object.keys(pts)) {
      types[code] = {
        enabled: typeEnabled(code),
        min: String(pts[code].mindepositamt ?? ''),
        max: String(pts[code].maxdepositamt ?? ''),
        // ค่าธรรมเนียมของผู้เล่น (% + บาท)
        pfeepct: String(pts[code].processingfeepct ?? '0'),
        pfeeconst: String(pts[code].processingfeeconst ?? '0'),
        // ค่าธรรมเนียมผ่านบุคคลที่สาม (% + บาท)
        dfeepct: String(pts[code].depositfeepct ?? '0'),
        dfeeconst: String(pts[code].depositfeeconst ?? '0')
      };
    }
    return {
      raw,                                   // เก็บไว้ประกอบตอนบันทึก (บอทไม่แตะ merchantinfo/vipids/platform)
      id: raw.thirdpartypaymentid,
      code: raw.thirdpartypaymentcode,
      name: (raw.thirdpartypaymentdisplayname && raw.thirdpartypaymentdisplayname['th-TH']) || '',
      currency: cur.currency || 'THB',
      status: cur.status,                    // สถานะฝาก (การรับชำระเงิน): 1=เปิด 2=สำรอง 4=ปิดการใช้งาน 8=ปิด
      supportpayout: (cur.supportpayout !== false),   // สถานะถอน: true=เปิด false=ปิด
      readonly: { updatedby: cur.updatedby, updatedat: cur.updatedat },
      values: {
        maxdailyamt: String(cur.maxdailyamt ?? ''),
        maxtotalamt: String(cur.maxtotalamt ?? ''),
        minpayoutamt: String(cur.minpayoutamt ?? ''),
        maxpayoutamt: String(cur.maxpayoutamt ?? ''),
        // ค่าธรรมเนียมถอน (% + บาท)
        payoutfeepct: String(cur.payoutfeepct ?? '0'),
        payoutfeeconst: String(cur.payoutfeeconst ?? '0'),
        remark: String(cur.remark ?? ''),
        amountsuggest: !!cur.amountsuggest,
        suggestamounts: Array.isArray(cur.suggestamounts) ? cur.suggestamounts.slice() : [],
        types
      }
    };
  },

  // บันทึกช่องทาง: ดึงค่าสด → ทับเฉพาะที่สั่ง → PUT กลับ
  // changes = { status?, maxdailyamt?, maxtotalamt?, minpayoutamt?, maxpayoutamt?,
  //             amountsuggest?, suggestamounts?, types?: {CODE:{enabled?,min?,max?}} }
  async saveChannel(site, token, channelId, changes) {
    const changed = [];
    const numStr = (v) => {
      const n = String(v).replace(/[, ]/g, '');
      if (!/^\d+(\.\d+)?$/.test(n)) throw new Error('ค่าตัวเลขไม่ถูกต้อง: ' + v);
      return n;
    };

    // แยกงาน: เปิด/ปิดประเภท (enabled) → ยิง API แบงก์ · อย่างอื่น → PUT ช่องทาง
    const typeToggles = [];   // [{code, on}]
    const CHAN_FIELDS = ['status', 'supportpayout', 'maxdailyamt', 'maxtotalamt', 'minpayoutamt', 'maxpayoutamt', 'payoutfeepct', 'payoutfeeconst', 'remark', 'amountsuggest', 'suggestamounts'];
    let needsChannel = CHAN_FIELDS.some(k => changes[k] !== undefined);
    if (changes.types && typeof changes.types === 'object') {
      for (const code of Object.keys(changes.types)) {
        const t = changes.types[code];
        if (!VALID_PAYTYPES.includes(code)) continue;
        if (t.min !== undefined || t.max !== undefined || t.pfeepct !== undefined || t.pfeeconst !== undefined || t.dfeepct !== undefined || t.dfeeconst !== undefined) needsChannel = true;
        if (t.enabled !== undefined) typeToggles.push({ code, on: !!t.enabled });
      }
    }
    if (!needsChannel && !typeToggles.length) return { changed: [], note: 'ไม่มีอะไรเปลี่ยน' };

    // ===== ส่วนที่ต้องแตะค่าช่อง (สถานะ/วงเงิน/min-max/ถอน) → โหลดช่อง + PUT =====
    if (needsChannel) {
      const raw = await getRawChannel(site, token, channelId);
      if (!raw.currencies || !raw.currencies.length) throw new Error('ไม่พบข้อมูลสกุลเงินของช่องทางนี้');
      const cur = raw.currencies.find(c => c.currency === 'THB') || raw.currencies[0];
      if (changes.status !== undefined) {
        const st = Number(changes.status);
        if (![1, 2, 4, 8].includes(st)) throw new Error('สถานะฝากไม่ถูกต้อง');
        if (cur.status !== st) { cur.status = st; changed.push('สถานะฝาก=' + st); }
      }
      if (changes.supportpayout !== undefined) {
        const b = !!changes.supportpayout;
        if (cur.supportpayout !== b) { cur.supportpayout = b; changed.push('สถานะถอน=' + (b ? 'เปิด' : 'ปิด')); }
      }
      for (const k of ['maxdailyamt', 'maxtotalamt', 'minpayoutamt', 'maxpayoutamt']) {
        if (changes[k] !== undefined) { const v = numStr(changes[k]); if (String(cur[k]) !== v) { cur[k] = v; changed.push(k + '=' + v); } }
      }
      if (changes.payoutfeepct !== undefined) { cur.payoutfeepct = numStr(changes.payoutfeepct); changed.push('ค่าธรรมเนียมถอน%=' + cur.payoutfeepct); }
      if (changes.payoutfeeconst !== undefined) { cur.payoutfeeconst = numStr(changes.payoutfeeconst); changed.push('ค่าธรรมเนียมถอนบาท=' + cur.payoutfeeconst); }
      if (changes.remark !== undefined) { cur.remark = String(changes.remark); changed.push('หมายเหตุ'); }
      if (changes.amountsuggest !== undefined) { cur.amountsuggest = !!changes.amountsuggest; changed.push('amountsuggest=' + cur.amountsuggest); }
      if (Array.isArray(changes.suggestamounts)) {
        const arr = changes.suggestamounts.map(x => Number(String(x).replace(/[, ]/g, '')));
        if (arr.some(n => !isFinite(n) || n < 0)) throw new Error('ปุ่มจำนวนเงินมีค่าไม่ถูกต้อง');
        cur.suggestamounts = arr; changed.push('ปุ่มเงินแนะนำ ' + arr.length + ' ปุ่ม');
      }
      // min/max/ค่าธรรมเนียม ราย type (อยู่ใน paymenttypesetting)
      if (changes.types) {
        const pts = cur.paymenttypesetting || (cur.paymenttypesetting = {});
        for (const code of Object.keys(changes.types)) {
          const t = changes.types[code];
          if (!VALID_PAYTYPES.includes(code)) continue;
          if (!(t.min !== undefined || t.max !== undefined || t.pfeepct !== undefined || t.pfeeconst !== undefined || t.dfeepct !== undefined || t.dfeeconst !== undefined)) continue;
          if (!pts[code]) { pts[code] = { mindepositamt: '10', maxdepositamt: '10000', processingfeepct: '0', processingfeeconst: '0', depositfeepct: '0', depositfeeconst: '0' }; changed.push('สร้าง ' + code); }
          if (t.min !== undefined) { pts[code].mindepositamt = numStr(t.min); changed.push(code + '.min=' + pts[code].mindepositamt); }
          if (t.max !== undefined) { pts[code].maxdepositamt = numStr(t.max); changed.push(code + '.max=' + pts[code].maxdepositamt); }
          if (t.pfeepct !== undefined) { pts[code].processingfeepct = numStr(t.pfeepct); changed.push(code + '.ผู้เล่น%'); }
          if (t.pfeeconst !== undefined) { pts[code].processingfeeconst = numStr(t.pfeeconst); changed.push(code + '.ผู้เล่นบาท'); }
          if (t.dfeepct !== undefined) { pts[code].depositfeepct = numStr(t.dfeepct); changed.push(code + '.บุคคลที่สาม%'); }
          if (t.dfeeconst !== undefined) { pts[code].depositfeeconst = numStr(t.dfeeconst); changed.push(code + '.บุคคลที่สามบาท'); }
          const mn = Number(pts[code].mindepositamt), mx = Number(pts[code].maxdepositamt);
          if (isFinite(mn) && isFinite(mx) && mx < mn) throw new Error(code + ': ฝากสูงสุดน้อยกว่าขั้นต่ำ');
        }
      }
      if (!Array.isArray(cur.depositPaymentTypes)) cur.depositPaymentTypes = Object.keys(cur.paymenttypesetting || {});
      if (changed.length) await boApi(site, token, 'PUT', `/thirdpartypayments/${encodeURIComponent(channelId)}`, raw);
    }

    // ===== เปิด/ปิดประเภท → ยิง API แบงก์ (ขนานทุกประเภท) =====
    if (typeToggles.length) {
      await Promise.all(typeToggles.map(async tg => {
        try {
          const banks = await boApi(site, token, 'GET', `/thirdpartypaymentbanks?thirdpartypaymentid=${encodeURIComponent(channelId)}&depositPaymentTypeEnum=${encodeURIComponent(tg.code)}&currency=THB`);
          const list = Array.isArray(banks) ? banks : [];
          if (!list.length) { changed.push((tg.on ? 'เปิด ' : 'ปิด ') + tg.code + ' (ไม่มีแบงก์)'); return; }
          const body = list.map(b => ({ thirdpartypaymentid: channelId, thirdpartypaymentbankcode: b.thirdpartypaymentbankcode, currency: 'THB', isenabled: tg.on }));
          await boApi(site, token, 'PUT', '/thirdpartypaymentbanks/isenabled', body);
          changed.push((tg.on ? 'เปิด ' : 'ปิด ') + tg.code + ' (' + body.length + ' แบงก์)');
        } catch (e) { throw new Error('เปิด/ปิด ' + tg.code + ' ไม่สำเร็จ: ' + (e.message || e)); }
      }));
    }
    return { changed };
  }
};

// ========================================================
// หน้า "รายชื่อธนาคาร" ของหลังบ้าน (การเงิน → ประเภทธนาคาร)
// สวิตช์ "การดูแลรักษาด้านหน้า" = ฟิลด์ status ของแบงก์
//   status 1 = ปกติ (หน้าบ้านใช้ได้)   status 2 = ปิดปรับปรุงหน้าบ้าน
//   ค่าอื่น (เช่น 0) = แบงก์ไม่ได้เปิดใช้ → บอทไม่แตะ (กันเผลอไปเปิดแบงก์ที่ปิดไว้)
// API เดียวกับที่หน้าเว็บหลังบ้านใช้: GET /banks/search , PUT /banks/{bankid}/status {status}
// ========================================================
const BANK_ST_NORMAL = 1, BANK_ST_MAINT = 2;

async function fetchSiteBanksPaged(site, token, currency, status) {
  const LIMIT = 100, out = [];
  for (let offset = 0; offset < 5000; offset += LIMIT) {
    const q = new URLSearchParams({ offset: String(offset), limit: String(LIMIT), sort: 'ASC', sortcolumn: 'banknameen' });
    if (currency) q.set('currency', currency);
    if (status !== undefined) q.set('status', String(status));
    const res = await boApi(site, token, 'GET', '/banks/search?' + q.toString());
    const rows = Array.isArray(res) ? res : ((res && (res.data || res.list || res.rows || res.content)) || []);
    out.push(...rows);
    const total = res && !Array.isArray(res) ? Number(res.total ?? res.totalCount ?? res.count) : NaN;
    if (rows.length < LIMIT || (isFinite(total) && out.length >= total)) break;
  }
  return out;
}
// หน้าค้นหาหลังบ้านตั้งตัวกรอง status=1 เป็นค่าเริ่มต้น → ถ้าเซิร์ฟเวอร์กรองเหมือนกัน แบงก์ที่ปิดปรับปรุง (2) จะหายจากรายการ
// จึงขอ status=2 แยกอีกรอบแล้วรวม (ตัดซ้ำด้วย bankid) — ถูกต้องไม่ว่าเซิร์ฟเวอร์จะกรองหรือไม่
async function fetchSiteBanks(site, token, currency) {
  const [base, maint] = await Promise.all([
    fetchSiteBanksPaged(site, token, currency),
    fetchSiteBanksPaged(site, token, currency, BANK_ST_MAINT).catch(() => [])
  ]);
  const seen = new Map();
  for (const b of base.concat(maint)) if (b && b.bankid != null && !seen.has(String(b.bankid))) seen.set(String(b.bankid), b);
  return [...seen.values()];
}

function normSiteBank(b) {
  const st = Number(b.status);
  return {
    bankid: String(b.bankid),
    name: b.banknameen || b.banknamesc || String(b.bankid),
    namesc: b.banknamesc || '',
    currency: b.currency || '',
    paymenttype: b.bankpaymenttype,
    status: st,
    maintenance: st === BANK_ST_MAINT,          // true = ปิดปรับปรุงหน้าบ้านอยู่
    open: st === BANK_ST_NORMAL,                // true = หน้าบ้านใช้ได้ (สวิตช์ "เปิด" ในหน้า FT)
    togglable: st === BANK_ST_NORMAL || st === BANK_ST_MAINT,
    image: b.bankimage || '',
    url: b.bankurl || ''
  };
}

const bankKey = s => String(s || '').trim().toLowerCase().replace(/\s+/g, ' ');

const BANK_PUT_CONC = 10;
const SITE_BANKS = {
  async list(site, token, currency) {
    const rows = (await fetchSiteBanks(site, token, currency)).map(normSiteBank);
    return { site_id: site.id, banks: rows, total: rows.length,
             open: rows.filter(b => b.open).length, closed: rows.filter(b => b.maintenance).length };
  },

  // banks: [{ bankid?, name?, open: true|false }]  — name = banknameen (ใช้ตอนสั่งหลายเว็บ เพราะ bankid แต่ละเว็บไม่ตรงกัน)
  // all:   true = เปิดทั้งหมด, false = ปิดทั้งหมด (เฉพาะแบงก์ที่ togglable)
  async set(site, token, banks, all, currency) {
    const current = (await fetchSiteBanks(site, token, currency)).map(normSiteBank);
    if (!current.length) throw new Error('ไม่พบรายชื่อธนาคารในหลังบ้าน');
    const byId = new Map(current.map(b => [b.bankid, b]));
    const byName = new Map();
    for (const b of current) for (const n of [b.name, b.namesc]) if (n) byName.set(bankKey(n), b);

    let wanted = [];          // [{bank, open}]
    const notFound = [], skipped = [];
    if (all === true || all === false) {
      for (const b of current) { if (b.togglable) wanted.push({ bank: b, open: all }); }
    } else {
      if (!Array.isArray(banks) || !banks.length) throw new Error('ไม่ได้ระบุธนาคารที่จะเปิด/ปิด');
      for (const x of banks) {
        const b = (x && x.bankid != null && byId.get(String(x.bankid))) || (x && x.name && byName.get(bankKey(x.name)));
        if (!b) { notFound.push((x && (x.name || x.bankid)) || '?'); continue; }
        if (!b.togglable) { skipped.push(b.name + ' (status=' + b.status + ')'); continue; }
        wanted.push({ bank: b, open: !!x.open });
      }
    }
    const diff = wanted.filter(w => w.bank.open !== w.open);

    // ยิงพร้อมกันทีละ BANK_PUT_CONC ตัว (หลังบ้านเป็น API ทีละแบงก์)
    const failed = [];
    let i = 0;
    const worker = async () => {
      while (i < diff.length) {
        const w = diff[i++];
        try {
          await boApi(site, token, 'PUT', `/banks/${encodeURIComponent(w.bank.bankid)}/status`,
                      { status: w.open ? BANK_ST_NORMAL : BANK_ST_MAINT });
        } catch (e) { failed.push(w.bank.name + ': ' + (e.message || e)); }
      }
    };
    await Promise.all(Array.from({ length: Math.min(BANK_PUT_CONC, diff.length) }, worker));

    // อ่านกลับเพื่อยืนยันค่าจริง
    const after = diff.length ? (await fetchSiteBanks(site, token, currency)).map(normSiteBank) : current;
    const afterById = new Map(after.map(b => [b.bankid, b]));
    const changed = [], notApplied = [];
    for (const w of diff) {
      const b = afterById.get(w.bank.bankid);
      if (b && b.open === w.open) changed.push((w.open ? 'เปิด ' : 'ปิด ') + w.bank.name);
      else if (!failed.some(f => f.startsWith(w.bank.name + ':'))) notApplied.push(w.bank.name);
    }
    const result = { site_id: site.id, changed, banks: after,
                     not_found: notFound, skipped, failed, not_applied: notApplied };
    // พังทั้งหมด = งาน failed ; พังบางตัว = งาน done แต่มีรายการ failed/not_applied ให้หน้าเว็บโชว์
    if (diff.length && !changed.length && (failed.length || notApplied.length)) {
      throw new Error('เปิด/ปิดธนาคารไม่สำเร็จ: ' + failed.concat(notApplied).join(' | '));
    }
    return result;
  }
};


// ========================================================
// หลังบ้านแบบ TCG (เช่น NM9)  —  platform = 'tcg'
//   api_base = https://<โดเมน>/tac/api      web_url = https://<โดเมน>
// ล็อกอิน 2 ขั้น: POST /login/password → 500 NEED_LOGIN_WITH_OTP → POST /login/otp {operatorName, code}
//   code = รหัส Google Authenticator 6 หลัก บอทสร้างเองจากรหัสลับ (ตั้งในหน้า FT พร้อมรหัสผ่าน ล็อกด้วยกุญแจเดียวกัน)
// ทุกคำขอหลังล็อกอินส่ง header: authorization=<token> (ไม่มี Bearer), operatorname, platform, environment, merchant
// คำตอบห่อแบบ { success, errorCode, message, value }
// ========================================================
const TCG_UI_VERSION = '20261117-dd3d4egjkmotv-5fea8e00';

// ----- Google Authenticator (TOTP RFC 6238: SHA1, 6 หลัก, 30 วิ) -----
function base32Decode(str) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(str || '').toUpperCase().replace(/[\s=-]/g, '');
  if (!clean || /[^A-Z2-7]/.test(clean)) throw new Error('รหัสลับ Google Authenticator ไม่ถูกต้อง (ต้องเป็นตัว A-Z และ 2-7)');
  let bits = 0, val = 0; const out = [];
  for (const ch of clean) { val = (val << 5) | A.indexOf(ch); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  return Buffer.from(out);
}
function totpAt(secret, step) {
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac('sha1', base32Decode(secret)).update(msg).digest();
  const o = h[h.length - 1] & 15;
  const n = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1000000).padStart(6, '0');
}
// รหัสเดียวกันใช้ซ้ำในช่วง 30 วิเดียวกันไม่ได้ (บางระบบนับเป็นผิด) → ถ้าเพิ่งใช้ไป รอรอบถัดไป
const totpLastStep = new Map();
async function nextTotp(siteId, secret) {
  let step = Math.floor(Date.now() / 30000);
  if (totpLastStep.get(siteId) >= step) {
    await new Promise(r => setTimeout(r, (step + 1) * 30000 - Date.now() + 300));
    step = Math.floor(Date.now() / 30000);
  }
  totpLastStep.set(siteId, step);
  return totpAt(secret, step);
}

function tcgTraceId() {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789$!_-';
  return Array.from(crypto.randomBytes(16), b => A[b % A.length]).join('');
}
function tcgHeaders(site, token, extra) {
  const origin = new URL(site.web_url).origin;
  const h = {
    'Content-Type': 'application/json', Accept: 'application/json, text/plain, */*',
    Origin: origin, Referer: origin + '/', 'User-Agent': UA,
    authorization: token || 'null', operatorname: (extra && extra.operator) || 'null',
    language: 'th_TH', customtimezone: 'undefined',
    platform: (extra && extra.platform) || '', environment: (extra && extra.environment) || '',
    'tac-trace-id': tcgTraceId(), 'tac-ui-version': TCG_UI_VERSION
  };
  if (extra && extra.merchant) { h.merchant = extra.merchant; h.merchantcode = extra.merchant; h.notpending = 'true'; }
  return h;
}
// ยิง API แบบดิบ คืน { status, body }  —  base เว้นว่าง = /tac/api (ค่าปริยาย) · ส่ง base มาเพื่อยิง /mcs_console/api
async function tcgFetch(site, method, path, body, token, extra, base) {
  const res = await fetch((base || site.api_base) + path, {
    method, headers: tcgHeaders(site, token, extra),
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS), ...boFetchOpts()
  });
  const text = await res.text();
  let data = null; try { data = text ? JSON.parse(text) : null; } catch (e) {}
  return { status: res.status, data, text };
}
const TCG_AUTH_ERR = /TOKEN|NOT_?LOGIN|LOGIN_?EXPIRED|SESSION|UNAUTHORI[ZS]ED|KICK/i;

async function tcgLogin(site, cred) {
  if (!cred.totp) throw new Error('หลังบ้าน TCG ต้องใส่รหัสลับ Google Authenticator ตอนตั้งบัญชีบอทในหน้า FT');
  base32Decode(cred.totp);   // เช็ครูปแบบก่อนยิง (กันนับรหัสผิด)
  const op = cred.userid;
  // ขั้น 1: รหัสผ่าน
  const r1 = await tcgFetch(site, 'POST', '/login/password', { operatorName: op, password: cred.password });
  let resp = r1.data;
  const ec1 = resp && resp.errorCode;
  if (!(resp && resp.success && resp.value && resp.value.token)) {
    if (ec1 !== 'NEED_LOGIN_WITH_OTP') {
      if (r1.status === 403 && !resp) throw new Error('หลังบ้านไม่ให้เข้า (403) — อาจจำกัด IP: ' + htmlSummary(r1.text));
      throw new Error('ล็อกอินไม่ผ่าน (' + r1.status + '): ' + ((resp && (resp.message || resp.errorCode)) || htmlSummary(r1.text)));
    }
    // ขั้น 2: รหัส Google Authenticator
    const code = await nextTotp(site.id, cred.totp);
    const r2 = await tcgFetch(site, 'POST', '/login/otp', { operatorName: op, code });
    resp = r2.data;
    if (!(resp && resp.success !== false && resp.token)) {
      const v = resp && resp.value;
      if (!(v && v.token)) throw new Error('รหัส Google Authenticator ไม่ผ่าน (' + r2.status + '): ' + ((resp && (resp.message || resp.errorCode)) || htmlSummary(r2.text)) + ' — เช็ครหัสลับที่ตั้งไว้');
      resp = v;
    }
  } else resp = resp.value;
  let merchant = '';
  try { const m = JSON.parse(resp.merchants || '[]'); merchant = (m[0] && m[0].merchantCode) || ''; } catch (e) {}
  if (!merchant) throw new Error('ล็อกอินได้ แต่ไม่พบรหัส merchant ของบัญชีนี้');
  // TCG ไม่บอกเวลาหมดอายุ → ถือว่าใช้ได้ 6 ชม. (ถ้าโดนตัดก่อน boApi จะล็อกอินใหม่ให้เอง)
  return { token: resp.token, exp: Date.now() + 6 * 3600 * 1000,
           extra: { operator: op, merchant, platform: resp.platform || 'TCG', environment: resp.environment || '' } };
}

// เรียก API หลังล็อกอิน → คืน value ; token ใช้ไม่ได้ → ล็อกอินใหม่แล้วลองซ้ำ 1 ครั้ง
async function tcgApi(site, token, method, path, body, _retried) {
  const sess = sessions.get(site.id) || {};
  const r = await tcgFetch(site, method, path, body, token, sess.extra);
  const d = r.data;
  const authFail = r.status === 401 || r.status === 403 || (d && d.success === false && TCG_AUTH_ERR.test(String(d.errorCode || '') + ' ' + String(d.message || '')));
  if (authFail) {
    sessions.delete(site.id);
    log('🔻 tcgApi', site.id, method, path, '→', r.status, (d && (d.errorCode || d.message)) || htmlSummary(r.text));
    if (!_retried) {
      try { const fresh = await ensureToken(site); return await tcgApi(site, fresh, method, path, body, true); } catch (e2) {}
    }
    const e = new Error('token หลังบ้านใช้ไม่ได้: ' + ((d && (d.message || d.errorCode)) || r.status)); e.httpStatus = 401; throw e;
  }
  if (r.status >= 400 || !d || d.success === false) {
    log('🔻 tcgApi', site.id, method, path, '→', r.status, 'body=' + (r.text || '').slice(0, 220).replace(/\s+/g, ' '));
    const e = new Error((d && (d.message || d.errorCode)) || ('HTTP ' + r.status)); e.httpStatus = r.status; throw e;
  }
  return d.value;
}
const tcgMerchant = site => ((sessions.get(site.id) || {}).extra || {}).merchant || '';

// ----- เรียก API ฝั่ง /mcs_console/api (คนละ base กับ /tac/api แต่ host เดียวกัน · ใช้ header/ token เดียวกัน) -----
function tcgMcsBase(site) { return new URL(site.web_url).origin + '/mcs_console/api'; }
async function tcgMcsApi(site, token, method, path, body, _retried) {
  const sess = sessions.get(site.id) || {};
  const r = await tcgFetch(site, method, path, body, token, sess.extra, tcgMcsBase(site));
  const d = r.data;
  const authFail = r.status === 401 || r.status === 403 || (d && d.success === false && TCG_AUTH_ERR.test(String(d.errorCode || '') + ' ' + String(d.message || '')));
  if (authFail && !_retried) {
    sessions.delete(site.id);
    try { const fresh = await ensureToken(site); return await tcgMcsApi(site, fresh, method, path, body, true); } catch (e2) {}
  }
  if (r.status >= 400 || !d || d.success === false) {
    log('🔻 tcgMcsApi', site.id, method, path.split('?')[0], '→', r.status, (d && (d.message || d.errorCode)) || (r.text || '').slice(0, 160).replace(/\s+/g, ' '));
    const e = new Error((d && (d.message || d.errorCode)) || ('HTTP ' + r.status)); e.httpStatus = r.status; throw e;
  }
  return d;   // คืนทั้งห่อ { success, value, ... }
}
const _sleep = ms => new Promise(r => setTimeout(r, ms));
// 'YYYY-MM-DD HH:mm:ss' ตามเวลา UTC+8 (เหมือนหน้าเว็บ TCG) โดยไม่ขึ้นกับ timezone ของ VPS
function tcgDateStr(ms) { return new Date(ms + 8 * 3600 * 1000).toISOString().slice(0, 19).replace('T', ' '); }

// ----- ช่องทางชำระเงิน (บัญชีบุคคลที่สาม) -----
// แปลงเป็นรูปแบบเดียวกับ K36 ให้หน้า FT ใช้ร่วมกันได้:
//   status (สถานะช่อง): accountStatus A→1 (เปิด)  I→4 (ปิดการใช้งาน)
//   supportpayout (ถอน): withdrawConfig.status A/I
//   types[รหัสประเภท]: depositMethods[] (status, minAmount, maxAmount, ค่าธรรมเนียม)
const TCG_TYPE_NAME = { TRUEMONEY: 'TrueMoney', QBT: 'โอนเงินผ่านธนาคารด่วน', PGMTB: 'การโอนเงินผ่าน QR ของธนาคาร', IPQR: 'PromptPay', TBQR: 'สแกน QR CODE เติมเงิน', PROMPTPAY: 'PROMPTPAY', TW: 'True Wallet' };
const tcgNum = v => (v === null || v === undefined) ? '' : String(v);
function fmtTcgTime(ms) {   // หน้าเว็บ TCG ส่งเวลาแก้ล่าสุดกลับเป็น 'YYYY-MM-DD HH:mm:ss' เวลา UTC+8
  if (typeof ms !== 'number') return ms;
  return new Date(ms + 8 * 3600 * 1000).toISOString().slice(0, 19).replace('T', ' ');
}
// สร้างข้อมูลสำหรับบันทึก จากค่าที่อ่านมา (ทำแบบเดียวกับหน้าเว็บ TCG
//  แต่พารามิเตอร์ผู้ให้บริการส่ง "ค่าเดิมที่อ่านมา" เสมอ ไม่ใช้ค่าเริ่มต้นแบบหน้าเว็บ)
function tcgBuildUpdate(raw, merchant) {
  const p = JSON.parse(JSON.stringify(raw));
  const ids = a => (a || []).map(x => (x && typeof x === 'object') ? x.paymentLabelId : x);
  p.depositPaymentLabels = p.depositPaymentLabelMode === 'Y' ? [] : ids(raw.depositPaymentLabels);
  p.withdrawPaymentLabels = p.withdrawPaymentLabelMode === 'Y' ? [] : ids(raw.withdrawPaymentLabels);
  const params = (raw.thirdPartyParameters && raw.thirdPartyParameters.params) || [];
  p.thirdPartyParameters = params.map(x => ({
    id: x.id, paramKeyName: x.paramKeyName, paramThirdParty: x.paramThirdParty,
    paramValue: (typeof x.paramValue === 'string' && /^\*+$/.test(x.paramValue)) ? null : x.paramValue,   // ค่าลับที่ถูกซ่อน (****) → null = ไม่แก้
    defaultValue: x.defaultValue, isDisplay: x.isDisplay, remarks: x.remarks, sensitivityLevel: x.sensitivityLevel
  }));
  p.lastUpdatedTime = fmtTcgTime(raw.lastUpdatedTime);
  p.qrImages = Array.isArray(raw.qrImages) ? raw.qrImages : [];
  p.merchantCode = merchant;
  return p;
}
async function tcgListRaw(site, token, status) {
  const v = await tcgApi(site, token, 'POST', '/relay/post/mcs-internal-v3-bankaccount-thirdparty-searchByPost',
    { merchantCode: tcgMerchant(site), accountStatus: status, page: { size: 500, page: 1, pageable: false } });
  return (v && v.list) || [];
}
const TCG = {
  async listChannels(site, token) {
    // หน้าเว็บกรอง accountStatus ทีละค่า → ขอทั้งเปิด (A) และปิด (I) แล้วรวม ไม่ให้ช่องที่ปิดไว้หายจากรายการ
    const [a, i] = await Promise.all([tcgListRaw(site, token, 'A'), tcgListRaw(site, token, 'I').catch(() => [])]);
    const seen = new Map();
    for (const x of a.concat(i)) if (x && x.bankAccountId != null && !seen.has(x.bankAccountId)) seen.set(x.bankAccountId, x);
    return [...seen.values()].map(x => ({ id: String(x.bankAccountId), code: x.displayAccountNumber || x.channelName, name: x.channelName, staticname: x.bankName || '' }));
  },
  // ====== ปรับยอดเข้ายูส (ฝากมือ) ======
  // ดึงข้อมูลยูส (ยืนยันว่ามีจริง + ระดับ VIP) — TCG ไม่มี balance ให้ตรงๆ
  async playerInfo(site, token, playerid) {
    const typed = String(playerid).trim();
    // ลองหลายรูปแบบตัวพิมพ์ (ตามพิมพ์ → เล็กหมด → ใหญ่หมด) เผื่อหลังบ้านสนตัวเล็ก/ใหญ่
    const variants = [...new Set([typed, typed.toLowerCase(), typed.toUpperCase()])];
    let u = typed, v = null;
    for (const cand of variants) {
      try {
        const d = await tcgMcsApi(site, token, 'GET',
          '/deposit/findUserForDepositRequest?merchantCode=' + encodeURIComponent(tcgMerchant(site)) + '&username=' + encodeURIComponent(cand));
        if (d && d.value && d.value.customerId != null) { v = d.value; u = cand; break; }
      } catch (_) { /* รูปแบบนี้ไม่เจอ ลองตัวถัดไป */ }
    }
    if (!v || v.customerId == null) throw new Error('ไม่พบรหัสสมาชิกนี้');
    const vip = (v.clubLabels && v.clubLabels[0] && v.clubLabels[0].labelName) || '';
    return {
      playerid: u, name: vip ? ('ระดับ ' + vip) : '', mobile: '', currency: 'THB',
      customerId: v.customerId, vip,
      available: null, total: null, pending: null, minDeposit: null, maxDeposit: null, avgDeposit: null,
      lastDeposit: null, lastWithdraw: null, banks: []
    };
  },
  // บัญชีธนาคารรับฝากของ TCG (ชื่อช่องในหน้าสร้างฝาก: KBANK/BBL) — คนละชุดกับช่องทางบุคคลที่สาม (88OKPay)
  async depositAccounts(site, token, username) {
    const merchant = tcgMerchant(site);
    let customerId = '';
    if (username) {
      try {
        const u = await tcgMcsApi(site, token, 'GET',
          '/deposit/findUserForDepositRequest?merchantCode=' + encodeURIComponent(merchant) + '&username=' + encodeURIComponent(String(username).trim()));
        customerId = (u && u.value && u.value.customerId) || '';
      } catch (e) {}
    }
    const d = await tcgMcsApi(site, token, 'GET',
      '/loadDepositBankAccountsByDepositType?merchantCode=' + encodeURIComponent(merchant) + '&depositType=&customerId=' + encodeURIComponent(customerId));
    const arr = (d && d.value) || [];
    return arr.map(a => {
      const b = a.bank || {};
      const acct = a.acctCode || b.bankCode || String(a.bankAccountId);
      return { id: String(a.bankAccountId), code: acct, name: acct, staticname: b.bankEnName || b.bankChName || acct };
    });
  },
  // ค้นรายการฝากของยูสวันนี้ (status: ''=ทั้งหมด, 'N'=ใหม่, 'P'=รอ approve) · endpoint ต่างกันตาม pending
  async _searchDeposits(site, token, username, status, pending) {
    const today = tcgDateStr(Date.now()).slice(0, 10);
    const q = new URLSearchParams({
      username, depositId: '', bankRef: '', depositStatus: status || '', amountFromStr: '', amountToStr: '',
      depositType: '', bankAcctIdList: '', searchDateMode: 'requestTime',
      dateFrom: today + ' 00:00:00', dateTo: today + ' 23:59:59', tcpBankCode: '',
      merchantCode: tcgMerchant(site), pageNo: '1', pageSize: '20'
    });
    if (!pending) { q.set('sortBy', 'depositId'); q.set('sortOrder', 'DESC'); }
    const path = pending ? '/relay/get/mcs-player-deposit-searchPending?' : '/relay/get/mcs-player-deposit-search?';
    const v = await tcgApi(site, token, 'GET', path + q.toString());
    return Array.isArray(v) ? v : (v && v.list) || [];
  },
  // หา depositId + version ของรายการที่เพิ่งสร้าง (สถานะ N ที่ยอด+บัญชีตรง เอาเลขล่าสุด)
  async _findNewDeposit(site, token, username, amt, bankAcctId) {
    for (let i = 0; i < 10; i++) {
      const rows = await this._searchDeposits(site, token, username, 'N', false).catch(() => []);
      const cand = rows.filter(r => String(r.bankAcctId) === String(bankAcctId) && Number(r.requestAmount) === Number(amt) && r.depositStatus === 'N');
      cand.sort((a, b) => String(b.depositId).localeCompare(String(a.depositId), undefined, { numeric: true }));
      if (cand.length) return { depositId: String(cand[0].depositId), version: cand[0].version };
      await _sleep(450);
    }
    return null;
  },
  // รอให้รายการขึ้นสถานะ P แล้วคืน version ใหม่ + wfTaskId
  async _findPending(site, token, username, depositId) {
    for (let i = 0; i < 10; i++) {
      const rows = await this._searchDeposits(site, token, username, 'P', true).catch(() => []);
      const m = rows.find(r => String(r.depositId) === String(depositId));
      if (m) return m;
      await _sleep(450);
    }
    return null;
  },
  // ฝากมือเข้ายูส (3 สเต็ป: createDeposit → ส่งตรวจสอบ(process) → ฝากสำเร็จ(approve))
  async deposit(site, token, p) {
    const amt = Number(p.amount);
    if (!p.playerid) throw new Error('ไม่ได้ระบุรหัสสมาชิก');
    if (!(amt > 0)) throw new Error('จำนวนเงินไม่ถูกต้อง');
    const merchant = tcgMerchant(site);
    const username = String(p.playerid).trim();

    // หลังบ้าน TCG ฝากเข้าบัญชี BBL เสมอ (ช่องที่เลือกในเว็บเป็นแค่ "ชื่อลงชีต" ไม่เกี่ยวกับหลังบ้าน)
    const accts = await this.depositAccounts(site, token, username).catch(() => []);
    const bbl = accts.find(a => /\bBBL\b|BKKB|bangkok/i.test(a.code + ' ' + a.staticname)) || accts[0];
    if (!bbl) throw new Error('ไม่พบบัญชีธนาคารรับฝาก BBL ของเว็บนี้ (เช็กที่หลังบ้านว่ามีบัญชี BBL เปิดอยู่ไหม)');
    const bankAcctId = bbl.id;
    if (p.sheet && !p.sheet.account) p.sheet.account = bbl.code;   // ถ้าเว็บไม่ได้ส่งชื่อลงชีต ใช้ชื่อบัญชี BBL

    // 1) สร้างคำขอฝาก (ไม่คืน depositId มาให้)
    await tcgApi(site, token, 'POST', '/relay/post/mcs-internal-v3-player-deposit-createDeposit', {
      merchantCode: merchant, username, depositType: 1, bankAcctId: Number(bankAcctId),
      requestDateString: tcgDateStr(Date.now()), requestAmount: amt, customerBankCharge: 0, bankCharge: ''
    });

    // 2) หาเลขรายการที่เพิ่งสร้าง (สถานะ N) + version
    const rec = await this._findNewDeposit(site, token, username, amt, bankAcctId);
    if (!rec) throw new Error('สร้างคำขอฝากแล้ว แต่หาเลขรายการไม่เจอ — เช็กที่หลังบ้านว่ารายการค้างอยู่ไหม');
    const depositId = rec.depositId;

    // 3) ส่งเพื่อตรวจสอบ (process)
    const body = {
      depositId, tpRefNo: null, payerBankAcctName: null, payerBankAcctNum: null,
      depositAmount: amt, bankRef: null, operatorRemark: null, internalRemark: null,
      version: rec.version, merchantCode: merchant
    };
    await tcgMcsApi(site, token, 'POST', '/deposit/process', Object.assign({}, body, { isProcessAndApprove: false }));

    // 4) รอสถานะ P → version ใหม่ + wfTaskId
    const pend = await this._findPending(site, token, username, depositId);
    if (!pend) throw new Error('ส่งตรวจสอบแล้ว แต่รายการยังไม่ขึ้นสถานะพร้อม approve (ลองกดฝากสำเร็จที่หลังบ้าน)');

    // 5) lock task (หน้าเว็บทำก่อนกดฝากสำเร็จ)
    if (pend.wfTaskId) {
      try { await tcgMcsApi(site, token, 'GET', '/task/lock?taskId=' + encodeURIComponent(pend.wfTaskId) + '&moduleType=' + encodeURIComponent('Process and Approve Deposit')); } catch (e) {}
    }

    // 6) ฝากเงินสำเร็จ (approve) — ยอดเข้ายูสจริง
    await tcgApi(site, token, 'POST', '/relay/post/mcs-v3-deposit-approve', Object.assign({}, body, { version: pend.version }));

    return { ok: true, playerid: username, amount: amt, orderno: depositId, orderBO: depositId, result: null };
  },

  async getRaw(site, token, channelId) {
    const q = new URLSearchParams({ bankAccountId: String(channelId), merchantCode: tcgMerchant(site) });
    const raw = await tcgApi(site, token, 'GET', '/relay/get/mcs-bankaccount-thirdparty-get?' + q);
    if (!raw || !Array.isArray(raw.depositMethods)) throw new Error('อ่านข้อมูลช่องทางไม่ได้');
    return raw;
  },
  async getChannel(site, token, channelId) {
    const raw = await TCG.getRaw(site, token, channelId);
    const wc = raw.withdrawConfig || {};
    const types = {};
    for (const m of raw.depositMethods) {
      const code = (m.bankTypes || []).join('+'); if (!code) continue;
      types[code] = {
        enabled: m.status === 'A', min: tcgNum(m.minAmount), max: tcgNum(m.maxAmount),
        pfeepct: tcgNum(m.playerCharge ?? 0), pfeeconst: tcgNum(m.playerChargeFixed ?? 0),
        dfeepct: tcgNum(m.vendorCharge ?? 0), dfeeconst: tcgNum(m.vendorChargeFixed ?? 0),
        amounts: Array.isArray(m.fixedAmounts) ? m.fixedAmounts.slice() : [],
        fixed: m.fixedAmount === 'Y', fixedonly: m.fixedAmountOnly === 'Y'   // จำนวนเงินที่กำหนด / จำนวนที่กำหนดเท่านั้น
      };
    }
    return {
      raw, platform: 'tcg',
      id: String(raw.bankAccountId), code: raw.displayAccountNumber || raw.channelName, name: raw.channelName || '',
      currency: 'THB',
      status: raw.accountStatus === 'A' ? 1 : 4,
      supportpayout: wc.status === 'A',
      readonly: { updatedby: raw.lastUpdatedBy, updatedat: raw.lastUpdatedTime },
      values: {
        maxdailyamt: tcgNum(raw.dailyDepositLimit), maxtotalamt: tcgNum(raw.depositBalanceLimit),
        minpayoutamt: tcgNum(wc.minAmount), maxpayoutamt: tcgNum(wc.maxAmount),
        payoutfeepct: tcgNum(wc.vendorCharge ?? 0), payoutfeeconst: tcgNum(wc.vendorChargeFixed ?? 0),
        remark: String(raw.remarks ?? ''), amountsuggest: false, suggestamounts: [], types
      }
    };
  },
  async saveChannel(site, token, channelId, changes) {
    const raw = await TCG.getRaw(site, token, channelId);
    const changed = [];
    const num = v => { const n = String(v).replace(/[, ]/g, ''); if (!/^\d+(\.\d+)?$/.test(n)) throw new Error('ค่าตัวเลขไม่ถูกต้อง: ' + v); return Number(n); };
    const numOrNull = v => (String(v).trim() === '' ? null : num(v));
    if (changes.status !== undefined) {
      const st = Number(changes.status);
      if (st === 2) throw new Error('หลังบ้าน TCG ไม่มีสถานะ "สำรอง"');
      if (![1, 4, 8].includes(st)) throw new Error('สถานะไม่ถูกต้อง');
      const v = st === 1 ? 'A' : 'I';
      if (raw.accountStatus !== v) { raw.accountStatus = v; changed.push('สถานะช่อง=' + (v === 'A' ? 'เปิด' : 'ปิด')); }
    }
    const wc = raw.withdrawConfig || (raw.withdrawConfig = {});
    if (changes.supportpayout !== undefined) {
      const v = changes.supportpayout ? 'A' : 'I';
      if (wc.status !== v) { wc.status = v; changed.push('สถานะถอน=' + (v === 'A' ? 'เปิด' : 'ปิด')); }
    }
    if (changes.maxdailyamt !== undefined) { raw.dailyDepositLimit = numOrNull(changes.maxdailyamt); changed.push('วงเงินฝากต่อวัน=' + (raw.dailyDepositLimit ?? 'ไม่จำกัด')); }
    if (changes.maxtotalamt !== undefined) { raw.depositBalanceLimit = numOrNull(changes.maxtotalamt); changed.push('วงเงินยอดคงเหลือ=' + (raw.depositBalanceLimit ?? 'ไม่จำกัด')); }
    if (changes.minpayoutamt !== undefined) { wc.minAmount = num(changes.minpayoutamt); changed.push('ถอนขั้นต่ำ=' + wc.minAmount); }
    if (changes.maxpayoutamt !== undefined) { wc.maxAmount = num(changes.maxpayoutamt); changed.push('ถอนสูงสุด=' + wc.maxAmount); }
    if (changes.payoutfeepct !== undefined) { wc.vendorCharge = num(changes.payoutfeepct); changed.push('ค่าธรรมเนียมถอน%=' + wc.vendorCharge); }
    if (changes.payoutfeeconst !== undefined) { wc.vendorChargeFixed = num(changes.payoutfeeconst); changed.push('ค่าธรรมเนียมถอนบาท=' + wc.vendorChargeFixed); }
    if (wc.minAmount != null && wc.maxAmount != null && wc.maxAmount && wc.maxAmount < wc.minAmount) throw new Error('ถอนสูงสุดน้อยกว่าขั้นต่ำ');
    if (changes.remark !== undefined) { raw.remarks = String(changes.remark) || null; changed.push('หมายเหตุ'); }
    if (changes.suggestamounts !== undefined && JSON.stringify(changes.suggestamounts) !== '[]') throw new Error('หลังบ้าน TCG ตั้งปุ่มจำนวนเงินแยกรายประเภท — ยังไม่รองรับจากหน้านี้');
    if (changes.types && typeof changes.types === 'object') {
      for (const code of Object.keys(changes.types)) {
        const t = changes.types[code] || {};
        const m = raw.depositMethods.find(x => (x.bankTypes || []).join('+') === code);
        if (!m) throw new Error('ช่องนี้ไม่มีประเภท ' + code + ' (หลังบ้าน TCG เพิ่มประเภทจากบอทไม่ได้)');
        if (t.enabled !== undefined) { const v = t.enabled ? 'A' : 'I'; if (m.status !== v) { m.status = v; changed.push((t.enabled ? 'เปิด ' : 'ปิด ') + code); } }
        if (t.min !== undefined) { m.minAmount = num(t.min); changed.push(code + '.min=' + m.minAmount); }
        if (t.max !== undefined) { m.maxAmount = num(t.max); changed.push(code + '.max=' + m.maxAmount); }
        if (t.pfeepct !== undefined) { m.playerCharge = num(t.pfeepct); changed.push(code + '.ผู้เล่น%'); }
        if (t.pfeeconst !== undefined) { m.playerChargeFixed = num(t.pfeeconst); changed.push(code + '.ผู้เล่นบาท'); }
        if (t.dfeepct !== undefined) { m.vendorCharge = num(t.dfeepct); changed.push(code + '.บุคคลที่สาม%'); }
        if (t.dfeeconst !== undefined) { m.vendorChargeFixed = num(t.dfeeconst); changed.push(code + '.บุคคลที่สามบาท'); }
        if (t.amounts !== undefined) {
          if (!Array.isArray(t.amounts)) throw new Error(code + ': รายการจำนวนเงินไม่ถูกต้อง');
          const arr = [...new Set(t.amounts.map(num))].filter(n => n > 0).sort((a, b) => a - b);
          if (arr.length > 50) throw new Error(code + ': ปุ่มจำนวนเงินมากเกิน 50 ปุ่ม');
          if (JSON.stringify(arr) !== JSON.stringify(m.fixedAmounts || [])) { m.fixedAmounts = arr; changed.push(code + '.ปุ่มเงิน=' + (arr.join(',') || 'ว่าง')); }
        }
        if (t.fixed !== undefined) { const v = t.fixed ? 'Y' : 'N'; if (m.fixedAmount !== v) { m.fixedAmount = v; changed.push(code + '.ปุ่มจำนวนเงิน=' + (t.fixed ? 'เปิด' : 'ปิด')); } }
        if (t.fixedonly !== undefined) { const v = t.fixedonly ? 'Y' : 'N'; if (m.fixedAmountOnly !== v) { m.fixedAmountOnly = v; changed.push(code + '.เฉพาะจำนวนที่กำหนด=' + (t.fixedonly ? 'เปิด' : 'ปิด')); } }
        if (m.fixedAmount === 'Y' && !(m.fixedAmounts || []).length) throw new Error((TCG_TYPE_NAME[code] || code) + ': เปิดปุ่มจำนวนเงินแต่ยังไม่มีจำนวนเงินสักปุ่ม');
        if (m.fixedAmountOnly === 'Y' && !(m.fixedAmounts || []).length) throw new Error((TCG_TYPE_NAME[code] || code) + ': "จำนวนที่กำหนดเท่านั้น" ต้องมีจำนวนเงินอย่างน้อย 1 ปุ่ม');
        if (m.maxAmount && m.maxAmount < m.minAmount) throw new Error(code + ': ฝากสูงสุดน้อยกว่าขั้นต่ำ');
      }
    }
    if (!changed.length) return { changed: [], note: 'ไม่มีอะไรเปลี่ยน' };
    // หลังบ้าน TCG ไม่ยอมให้เปิดประเภทที่ "ฝากสูงสุด" = 0 → แจ้งเป็นภาษาไทยก่อนส่ง
    for (const m of raw.depositMethods) {
      if (m.status !== 'A' || Number(m.maxAmount) > 0) continue;
      const code = (m.bankTypes || []).join('+');
      throw new Error('เปิด ' + (TCG_TYPE_NAME[code] || code) + ' ไม่ได้: ยังไม่ได้ตั้ง "ฝากสูงสุด" (ตอนนี้ 0) — ใส่ฝากขั้นต่ำ/สูงสุดของประเภทนี้ก่อน แล้วเปิดพร้อมกันในครั้งเดียว');
    }
    await tcgApi(site, token, 'POST', '/relay/post/mcs-bankaccount-thirdparty-update', tcgBuildUpdate(raw, tcgMerchant(site)));
    return { changed };
  }
};

// ----- เปิด/ปิดธนาคาร = "วิธีถอน" (isWithdrawActive Y/N) — บันทึกทั้งรายการในคำขอเดียว -----
async function tcgWithdrawMethods(site, token) {
  const v = await tcgApi(site, token, 'GET', '/relay/get/mcs-v3-bankcard-setting-withdrawMethod-get');
  if (!Array.isArray(v)) throw new Error('อ่านรายการธนาคารถอนไม่ได้');
  return v;
}
// รหัสธนาคารของ TCG → ชื่อแบบหลังบ้าน K36 (banknameen) ให้หน้า FT รวมเป็นแถวเดียวกัน
// สั่ง "ปิด Bangkok Bank" ครั้งเดียว = ปิดทั้งเว็บ K36 และ TCG · ชื่อเดิม (ไทย) ยังใช้สั่งได้
const TCG_BANK_NAME = {
  BKKBTHBK: 'Bangkok Bank', KKB: 'Kasikorn Bank', SCB: 'Siam Commercial Bank', Krungsri: 'Bank of Ayudhya',
  GSB: 'Government Savings Bank', TMB: 'TMBThanachart Bank', KRTHTHBK: 'Krung Thai Bank', CIMBTH: 'CIMB Thai',
  UOBTH: 'UOB Bank', BAAC: 'Bank for Agriculture and Agricultural Cooperatives', KKB2: 'Kiatnakin Bank',
  TISCO: 'Tisco Bank', BOCTH: 'Bank of China', ICBCTH: 'Industrial and Commercial Bank of China Limited',
  GHB: 'Government Housing Bank', HSBCTH: 'HSBC', LHBANK: 'Land And Houses Bank',
  SCBTH: 'STANDARD CHARTERED BANK (THAI)', MegaTH: 'Mega International Commercial Bank', TCRB: 'Thai Credit Bank',
  ISBT: 'Islamic Bank of Thailand', SMBCTH: 'Sumitomo Mitsui Banking Corporation', MHCBTH: 'MIZUHO CORPORATE BANK, LTD.',
  DBBKTH: 'Deutsche Bank', THB_CITI: 'Citibank Thailand', THB_EXIM: 'Export-Import Bank of Thailand', THB_SME: 'SME BANK'
};
function normTcgBank(x) {
  const open = x.isWithdrawActive === 'Y';
  const local = x.bankEnName || x.bankChName || x.bankCode;
  return {
    bankid: x.withdrawMethodGroup + ':' + x.bankId, name: TCG_BANK_NAME[x.bankCode] || local,
    namesc: local, code: x.bankCode || '', currency: x.currency || 'THB', paymenttype: x.groupName,
    status: open ? BANK_ST_NORMAL : BANK_ST_MAINT, maintenance: !open, open, togglable: true,
    image: x.bankIcon || '', url: ''
  };
}
const TCG_BANKS = {
  async list(site, token) {
    const rows = (await tcgWithdrawMethods(site, token)).map(normTcgBank);
    return { site_id: site.id, banks: rows, total: rows.length, open: rows.filter(b => b.open).length, closed: rows.filter(b => b.maintenance).length };
  },
  async set(site, token, banks, all) {
    const [raw, bind] = await Promise.all([
      tcgWithdrawMethods(site, token),
      tcgApi(site, token, 'GET', '/relay/get/mcs-v3-bankcard-setting-bindRestriction-get')
    ]);
    if (!raw.length) throw new Error('ไม่พบรายชื่อธนาคารในหลังบ้าน');
    const cur = raw.map(normTcgBank);
    const byId = new Map(cur.map((b, i) => [b.bankid, i])), byName = new Map();
    cur.forEach((b, i) => { for (const n of [b.name, b.namesc, b.code]) if (n) byName.set(bankKey(n), i); });
    const want = new Map(); const notFound = [];
    if (all === true || all === false) cur.forEach((b, i) => want.set(i, all));
    else {
      if (!Array.isArray(banks) || !banks.length) throw new Error('ไม่ได้ระบุธนาคารที่จะเปิด/ปิด');
      for (const x of banks) {
        let i;
        if (x && x.bankid != null) i = byId.get(String(x.bankid));
        if (i === undefined && x && x.name) i = byName.get(bankKey(x.name));
        if (i === undefined) { notFound.push((x && (x.name || x.bankid)) || '?'); continue; }
        want.set(i, !!x.open);
      }
    }
    const diff = [...want].filter(([i, open]) => cur[i].open !== open);
    if (diff.length) {
      for (const [i, open] of diff) raw[i].isWithdrawActive = open ? 'Y' : 'N';
      const body = {
        withdrawBankCardSetting: { allowedWithdrawMethodType: (bind && bind.allowedWithdrawMethodType) ?? null,
                                   hasBindCardRestriction: (bind && bind.hasBindCardRestriction) || 'Y', merchantCode: tcgMerchant(site) },
        withdrawMethodSettings: raw.map((x, i) => Object.assign({}, x, { index: i, key: x.bankCode + '_' + (i + 1), group: x.withdrawMethodGroup }))
      };
      await tcgApi(site, token, 'POST', '/relay/post/mcs-v3-bankcard-setting-withdrawMethod-save', body);
    }
    // อ่านกลับเพื่อยืนยันค่าจริง
    const after = diff.length ? (await tcgWithdrawMethods(site, token)).map(normTcgBank) : cur;
    const afterById = new Map(after.map(b => [b.bankid, b]));
    const changed = [], notApplied = [];
    for (const [i, open] of diff) {
      const b = afterById.get(cur[i].bankid);
      if (b && b.open === open) changed.push((open ? 'เปิด ' : 'ปิด ') + cur[i].name); else notApplied.push(cur[i].name);
    }
    if (diff.length && !changed.length) throw new Error('เปิด/ปิดธนาคารไม่สำเร็จ: ' + notApplied.join(' | '));
    return { site_id: site.id, changed, banks: after, not_found: notFound, skipped: [], failed: [], not_applied: notApplied };
  }
};

const PLATFORMS = { k36: K36, tf6: K36, tcg: TCG, default: K36 };
function platformOf(site) { return PLATFORMS[site.platform] || PLATFORMS.default; }

// ---------- จัดการคิวงาน bo_tasks ----------
async function claimTask(task) {
  // จองงานแบบอะตอมมิก: เปลี่ยน queued→running เฉพาะถ้ายัง queued แล้ว "ตรวจว่าจองได้จริง"
  // ถ้าอีกโปรเซส/อีกลูปจองไปก่อน PATCH จะไม่โดนแถวใด (คืน []) → คืน false เพื่อข้าม ห้ามทำซ้ำ (กันเงินเข้าซ้ำ)
  const rows = await sb('PATCH',
    `bo_tasks?id=eq.${task.id}&status=eq.queued`,
    { status: 'running', started_at: new Date().toISOString() },
    'return=representation');
  return Array.isArray(rows) && rows.length > 0;
}

async function runTask(site, token, task) {
  const P = platformOf(site);
  const a = task.action;
  const p = task.params || {};
  if (a === 'list_channels') {
    return { channels: await P.listChannels(site, token) };
  }
  if (a === 'get_all_channels') {
    // ดึงทุกช่อง + ค่าปัจจุบัน ในงานเดียว (ให้เว็บ cache ไว้ สลับช่องขึ้นทันที)
    const list = await P.listChannels(site, token);
    const out = new Array(list.length);
    // ดึงค่าหลายช่อง "พร้อมกันทีละ 4" (เดิมทีละช่องต่อคิวกัน ช้ามาก)
    const CONC = 4;
    let i = 0;
    const worker = async () => {
      while (i < list.length) {
        const idx = i++; const ch = list[idx];
        const item = { id: ch.id, code: ch.code, name: ch.name, staticname: ch.staticname };
        try { const d = await P.getChannel(site, token, ch.id); delete d.raw; item.data = d; }
        catch (e) { item.error = e.message || String(e); }   // ช่องที่ดึงไม่ได้ ไม่ทำให้ทั้งชุดพัง
        out[idx] = item;
      }
    };
    await Promise.all(Array.from({ length: Math.min(CONC, list.length) }, worker));
    return { channels: out };
  }
  if (a === 'get_channel') {
    if (!p.channel_id) throw new Error('ไม่ได้ระบุช่องทาง');
    const c = await P.getChannel(site, token, p.channel_id);
    delete c.raw; // ไม่ต้องเก็บค่าดิบลงผลลัพธ์
    return c;
  }
  if (a === 'save_channel') {
    if (!p.channel_id) throw new Error('ไม่ได้ระบุช่องทาง');
    if (!task.confirmed) throw new Error('ต้องกดยืนยันก่อนบันทึก');
    const r = await P.saveChannel(site, token, p.channel_id, p.changes || {});
    syncOneChannel(site, token, p.channel_id);   // อัปเดต snapshot ของช่องนี้ให้สด (ไม่รอผล)
    return r;
  }
  // ----- หน้า "รายชื่อธนาคาร" (สวิตช์การดูแลรักษาด้านหน้า) -----
  // สั่งหลายเว็บพร้อมกัน = หน้าเว็บสร้างงานแยก 1 งาน/เว็บ (ใส่ batch_id เดียวกันใน params) บอททำขนานกันเอง
  const BANKS = isTcg(site) ? TCG_BANKS : SITE_BANKS;
  if (a === 'list_site_banks') {
    return await BANKS.list(site, token, p.currency);
  }
  if (a === 'set_site_banks') {
    if (!task.confirmed) throw new Error('ต้องกดยืนยันก่อนบันทึก');
    const r = await BANKS.set(site, token, p.banks, p.all, p.currency);
    if (p.batch_id) r.batch_id = p.batch_id;
    return r;
  }
  if (a === 'player_lookup') {
    if (!p.playerid) throw new Error('ไม่ได้ระบุรหัสสมาชิก');
    if (typeof P.playerInfo !== 'function') throw new Error('แพลตฟอร์มนี้ยังไม่รองรับการค้นยูส');
    return await P.playerInfo(site, token, String(p.playerid).trim());
  }
  if (a === 'deposit_form') {
    if (typeof P.depositForm !== 'function') throw new Error('แพลตฟอร์มนี้ยังไม่รองรับ');
    return await P.depositForm(site, token, p.channelid);
  }
  if (a === 'deposit_player') {
    if (!task.confirmed) throw new Error('ต้องกดยืนยันก่อนฝาก');
    if (typeof P.deposit !== 'function') throw new Error('แพลตฟอร์มนี้ยังไม่รองรับการฝากเข้ายูส');
    let dep;
    try {
      dep = await P.deposit(site, token, p);
    } catch (e) {
      // กัน "ขึ้นพลาด แต่จริงๆ เข้าแล้ว" (หลังบ้านตอบช้า/เน็ตหลุด หลัง 20 วิ) → อย่าเพิ่งบอกพลาด ไปเช็คหลังบ้านก่อน
      const looksTimeout = e.name === 'TimeoutError' || e.name === 'AbortError'
        || /timeout|aborted|network|fetch failed|socket|ECONN|ETIMEDOUT|EAI_AGAIN/i.test(e.message || '');
      if (looksTimeout && typeof P.findDeposit === 'function' && p.orderno) {
        let rec = null;
        try { const tk = await ensureToken(site); rec = await P.findDeposit(site, tk, p.playerid, p.orderno); } catch (_) {}
        if (rec) {
          log('🛟 กู้สถานะฝาก', site.id, p.playerid, p.orderno, '— เข้าแล้วจริง (หลัง timeout) ไม่ต้องเติมซ้ำ');
          dep = { ok: true, recovered: true, playerid: String(p.playerid).trim(), amount: Number(p.amount),
                  orderno: String(p.orderno).trim(), orderBO: findOrderNo(rec, p.channelcode) || '', result: rec };
        } else {
          const err = new Error('⚠️ ไม่แน่ใจว่าเข้าหรือยัง (หลังบ้านตอบช้า) — กรุณาตรวจที่หลังบ้านก่อนเติมซ้ำ');
          err.uncertain = true; throw err;
        }
      } else { throw e; }
    }
    // ดึงเลขออร์เดอร์หลังบ้าน + เขียนชีต "เบื้องหลัง" (ไม่รอ) → ตอบกลับไว ไม่หน่วง
    if (p.sheet && process.env.SHEET_WEBHOOK_URL) {
      (async () => {
        try {
          if (!dep.orderBO && typeof P.fetchOrderBO === 'function') {
            dep.orderBO = await P.fetchOrderBO(site, token, p.playerid, p.channelcode, p.orderno).catch(() => '');
          }
          await writeSheet(p, dep);
        } catch (e) { log('⚠️ เขียนชีตเบื้องหลังพลาด', site.id, e.message || e); }
      })();
    }
    return dep;
  }
  if (a === 'sheet_summary') return await readSheet(p.date);
  if (a === 'ping') return { ok: true, name: site.name };
  throw new Error('ไม่รู้จักคำสั่ง: ' + a);
}

// ล็อกต่อเว็บ: กันวงจรหลัก/วงจรเร็วหยิบงานของเว็บเดียวกันพร้อมกัน (แต่ต่างเว็บทำขนานกันได้)
const siteBusy = new Set();
async function processTasks(site, token) {
  if (siteBusy.has(site.id)) return;
  siteBusy.add(site.id);
  try { await processTasksLocked(site, token); } finally { siteBusy.delete(site.id); }
}
async function processTasksLocked(site, token) {
  // หยิบงานที่ค้างของเว็บนี้ ทีละงาน (เรียงเก่าสุดก่อน)
  const tasks = await sb('GET',
    `bo_tasks?site_id=eq.${encodeURIComponent(site.id)}&status=eq.queued&order=created_at.asc&limit=5&select=*`);
  for (const task of (tasks || [])) {
    // หมดอายุ? (กันงานค้างนานแล้วเพิ่งมาทำ)
    if (task.expires_at && new Date(task.expires_at).getTime() < Date.now()) {
      await sb('PATCH', `bo_tasks?id=eq.${task.id}&status=eq.queued`,
        { status: 'expired', finished_at: new Date().toISOString(), error: 'หมดอายุก่อนทำ' });
      continue;
    }
    if (!(await claimTask(task))) continue;   // ถูกจองไปแล้วโดยตัวอื่น → ข้าม ห้ามทำซ้ำ (กันเงินเข้าซ้ำ)
    try {
      const tk = await ensureToken(site);   // token สดเสมอต่อ 1 งาน (หลังบ้านใช้ token ได้ทีละอัน)
      const result = await runTask(site, tk, task);
      await sb('PATCH', `bo_tasks?id=eq.${task.id}`,
        { status: 'done', finished_at: new Date().toISOString(), result, error: null });
      log('✔️', site.id, task.action, Array.isArray(result.changed) ? ('(' + result.changed.join(', ') + ')') : '');
    } catch (e) {
      const msg = e.name === 'TimeoutError' ? 'ติดต่อหลังบ้านไม่ได้ (หมดเวลา)' : (e.message || String(e));
      await sb('PATCH', `bo_tasks?id=eq.${task.id}`,
        { status: 'failed', finished_at: new Date().toISOString(), error: msg });
      log('✖️', site.id, task.action, msg);
      if (e.httpStatus === 401 || e.httpStatus === 403) break; // token มีปัญหา เลิกทำรอบนี้
    }
  }
}

// ---------- วงจรหลัก ----------
let running = false;
async function loop() {
  if (running) return;
  running = true;
  try {
    const sites = await sb('GET', 'bo_sites?enabled=eq.true&select=id,name,web_url,api_base,cred_cipher,cipher_fp,platform');
    const ids = new Set(sites.map(s => s.id));
    for (const id of sessions.keys()) if (!ids.has(id)) sessions.delete(id);
    for (const id of fastSiteCache.keys()) if (!ids.has(id)) fastSiteCache.delete(id);   // ล้างเว็บที่ปิด/ลบ ไม่ให้ค้าง
    for (const site of sites) {
      try {
        await handleSite(site);
      } catch (e) {
        log('⚠️', site.id, e.message);
      }
    }
  } catch (e) {
    log('⚠️ รอบนี้ผิดพลาด:', e.message);
  } finally {
    running = false;
  }
}

// ให้ Railway เช็กได้ว่าบอทยังมีชีวิต (ไม่เปิดเผยข้อมูลใด ๆ)
const PORT = process.env.PORT;
if (PORT) {
  http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('ok');
  }).listen(PORT, () => log('🌐 health check พอร์ต', PORT));
}

// เช็ก IP ขาออกของ Railway (ใช้แจ้งทีมหลังบ้านถ้าต้องเพิ่ม IP)
fetch('https://api.ipify.org?format=json', { signal: AbortSignal.timeout(8000) })
  .then(r => r.json()).then(d => log('🌍 IP ขาออกของบอท:', d.ip)).catch(() => {});

if (PROXY_URL) {
  log('🔌 ใช้ proxy สำหรับหลังบ้าน:', PROXY_URL.replace(/\/\/[^@]*@/, '//***@'));
  fetch('https://api.ipify.org?format=json', { signal: AbortSignal.timeout(12000), ...boFetchOpts() })
    .then(r => r.json()).then(d => log('🌍 IP ที่หลังบ้านจะเห็น (ผ่าน proxy):', d.ip)).catch(e => log('⚠️ เช็ก IP ผ่าน proxy ไม่ได้:', e.message));
} else {
  log('⚠️ ยังไม่ได้ตั้ง PROXY_URL — บอทจะต่อหลังบ้านตรง ๆ (อาจโดนบล็อก IP)');
}
// ---------- วงจรเร็ว: เช็กคิวงานถี่ ๆ (ไม่ล็อกอินซ้ำ ใช้ token ที่ cache ไว้) ----------
let fastRunning = false;
const FAST_POLL_MS = 300;   // เช็กงานใหม่ทุก 0.3 วินาที
async function fastLoop() {
  if (fastRunning) return; // ไม่รอ loop หลักแล้ว — ใช้ล็อกต่อเว็บ (siteBusy) แทน
  fastRunning = true;
  try {
    const rows = await sb('GET', 'bo_tasks?status=eq.queued&select=site_id&limit=20');
    if (rows && rows.length) {
      // เว็บที่ล็อกอินแล้วเท่านั้น (ที่ยังไม่ล็อกอินปล่อยให้ loop หลักจัดการ)
      const siteIds = [...new Set(rows.map(r => r.site_id))].filter(sid => {
        const s = sessions.get(sid); return s && s.token && fastSiteCache.get(sid);
      });
      // ประมวลผลทุกเว็บ "พร้อมกัน" (แต่ละเว็บคนละ session/หลังบ้าน จึงขนานได้)
      const CONC = 12;
      let i = 0;
      const worker = async () => {
        while (i < siteIds.length) {
          const sid = siteIds[i++];
          const s = sessions.get(sid), site = fastSiteCache.get(sid);
          if (!s || !s.token || !site) continue;
          try { await processTasks(site, s.token); } catch (e) { log('⚠️ fast', sid, e.message); }
        }
      };
      await Promise.all(Array.from({ length: Math.min(CONC, siteIds.length) }, worker));
    }
  } catch (e) {
    // เงียบไว้ ไม่ log รัว ๆ
  } finally {
    fastRunning = false;
  }
}

// ---------- Snapshot: เก็บช่องทาง+ค่าทุกเว็บไว้ใน Supabase ให้เว็บอ่านได้ทันที ----------
async function syncSiteChannels(site, token) {
  const P = platformOf(site);
  const list = await P.listChannels(site, token);
  const rows = new Array(list.length);
  const CONC = 4; let i = 0;
  const worker = async () => {
    while (i < list.length) {
      const idx = i++; const ch = list[idx];
      const row = { site_id: site.id, channel_id: String(ch.id), code: ch.code || null, name: ch.name || null, staticname: ch.staticname || null, data: null, err: null, updated_at: new Date().toISOString() };
      try { const d = await P.getChannel(site, token, ch.id); delete d.raw; row.data = d; }
      catch (e) { row.err = e.message || String(e); }
      rows[idx] = row;
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONC, list.length) }, worker));
  if (rows.length) {
    await sb('POST', 'bo_channels?on_conflict=site_id,channel_id', rows, 'resolution=merge-duplicates,return=minimal');
    // ลบช่องที่ไม่มีในหลังบ้านแล้วออกจาก snapshot (กันช่องผีค้าง) — ทำเฉพาะตอนได้ list ที่ถูกต้อง
    try {
      const inList = rows.map(r => '"' + String(r.channel_id).replace(/["\\]/g, '') + '"').join(',');
      await sb('DELETE', `bo_channels?site_id=eq.${encodeURIComponent(site.id)}&channel_id=not.in.(${encodeURIComponent(inList)})`);
    } catch (e) { /* ลบไม่สำเร็จไม่เป็นไร รอบหน้าค่อยลบ */ }
  }
  return rows.length;
}
// อัปเดต snapshot ของช่องเดียว (เรียกหลังบันทึกสำเร็จ ให้ข้อมูลสดทันที)
async function syncOneChannel(site, token, channelId) {
  try {
    const P = platformOf(site);
    const d = await P.getChannel(site, token, channelId);
    delete d.raw;
    await sb('POST', 'bo_channels?on_conflict=site_id,channel_id',
      [{ site_id: site.id, channel_id: String(channelId), data: d, err: null, updated_at: new Date().toISOString() }],
      'resolution=merge-duplicates,return=minimal');
  } catch (e) { /* เงียบ */ }
}
let syncRunning = false;
async function syncLoop() {
  if (syncRunning) return; syncRunning = true;
  try {
    const sites = [...fastSiteCache.values()];
    for (const site of sites) {
      const s = sessions.get(site.id);
      if (!s || !s.token) continue;
      try { const n = await syncSiteChannels(site, s.token); log('🗂️ snapshot', site.id, n, 'ช่อง'); }
      catch (e) { log('⚠️ snapshot', site.id, e.message); }
    }
  } finally { syncRunning = false; }
}
const SYNC_MS = 150 * 1000;   // รีเฟรช snapshot ทุก 2.5 นาที

// ---------- ตั้งเวลาเปิด/ปิดธนาคารประจำวัน ----------
// ตารางเวลาเก็บใน settings: key 'ft_bank_schedules' = JSON array (หน้าเว็บ FT เป็นคนแก้)
//   { id, label, action:'open'|'close', time:'HH:MM', days:'daily'|[0-6 (0=อา)],
//     sites:'all'|[site_id], scope:'all'|'pick', banks:[ชื่อธนาคาร], on:true|false }
// สถานะการรันเก็บแยก key 'ft_bank_schedule_runs' = { [id]: { key, at, batch, sites } } (กันรันซ้ำ / ไม่ชนตอนหน้าเว็บแก้ตาราง)
// เวลาอิงไทย (Asia/Bangkok) · ถ้าบอทดับตอนถึงเวลา จะตามรันให้ภายใน 10 นาที เลยจากนั้นข้าม (กันเปิด/ปิดผิดจังหวะ)
const SCHED_KEY = 'ft_bank_schedules', SCHED_RUNS_KEY = 'ft_bank_schedule_runs';
const SCHED_POLL_MS = 20 * 1000, SCHED_GRACE_MIN = 10;

function bangkokNow() {
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Asia/Bangkok', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', weekday: 'short', hour12: false
  }).formatToParts(new Date()).map(x => [x.type, x.value]));
  const dow = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(p.weekday);
  return { date: `${p.year}-${p.month}-${p.day}`, minutes: (Number(p.hour) % 24) * 60 + Number(p.minute), dow };
}
async function getSetting(key) {
  const rows = await sb('GET', `settings?key=eq.${encodeURIComponent(key)}&select=value`);
  if (!rows || !rows.length || rows[0].value == null) return null;
  try { return JSON.parse(rows[0].value); } catch (e) { return null; }
}
async function putSetting(key, obj) {
  const value = JSON.stringify(obj);
  const upd = await sb('PATCH', `settings?key=eq.${encodeURIComponent(key)}`, { value }, 'return=representation');
  if (!upd || !upd.length) await sb('POST', 'settings', [{ key, value }]);
}

// คืนรายการที่ "ถึงเวลา" ตอนนี้ (ยังไม่เคยรันรอบนี้)
function dueSchedules(list, runs, now) {
  const out = [];
  for (const s of (Array.isArray(list) ? list : [])) {
    if (!s || !s.on || !s.id || !/^\d{1,2}:\d{2}$/.test(s.time || '')) continue;
    if (s.action !== 'open' && s.action !== 'close') continue;
    if (s.days !== 'daily' && !(Array.isArray(s.days) && s.days.map(Number).includes(now.dow))) continue;
    const [hh, mm] = s.time.split(':').map(Number);
    const at = hh * 60 + mm, late = now.minutes - at;
    if (late < 0 || late > SCHED_GRACE_MIN) continue;
    const runKey = now.date + ' ' + s.time;          // แก้เวลาใหม่ในวันเดียวกัน = รอบใหม่ รันได้
    if (runs[s.id] && runs[s.id].key === runKey) continue;
    out.push({ s, runKey });
  }
  return out;
}

let schedRunning = false;
async function scheduleLoop() {
  if (schedRunning) return; schedRunning = true;
  try {
    const list = await getSetting(SCHED_KEY);
    if (!Array.isArray(list) || !list.length) return;
    const runs = (await getSetting(SCHED_RUNS_KEY)) || {};
    const due = dueSchedules(list, runs, bangkokNow());
    if (!due.length) return;

    const sites = await sb('GET', 'bo_sites?enabled=eq.true&select=id');
    const allIds = (sites || []).map(x => x.id);
    for (const { s, runKey } of due) {
      const targets = s.sites === 'all' || !Array.isArray(s.sites) ? allIds : s.sites.filter(id => allIds.includes(id));
      const open = s.action === 'open';
      const params = s.scope === 'pick'
        ? { banks: (s.banks || []).map(name => ({ name, open })) }
        : { all: open };
      const batch = 'sch-' + s.id + '-' + Date.now().toString(36);
      // จดว่ารันแล้ว "ก่อน" สร้างงาน — ถ้าสร้างงานพังกลางทาง จะไม่ยิงซ้ำรัว ๆ
      runs[s.id] = { key: runKey, at: new Date().toISOString(), batch, sites: targets };
      await putSetting(SCHED_RUNS_KEY, runs);
      if (!targets.length || (s.scope === 'pick' && !params.banks.length)) { log('⏰ ข้าม', s.label || s.id, '(ไม่มีเว็บ/ธนาคาร)'); continue; }
      params.batch_id = batch;
      const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
      await sb('POST', 'bo_tasks', targets.map(site_id => ({
        site_id, action: 'set_site_banks', params, confirmed: true, batch_id: batch,
        created_by: 'ตั้งเวลา: ' + (s.label || s.time), expires_at: expires
      })));
      sb('POST', 'system_logs', [{ action: 'FT_BANK_SCHEDULE', performed_by: 'ตั้งเวลา',
        detail: JSON.stringify({ v: 1, id: s.id, label: s.label, action: s.action, time: s.time, scope: s.scope, banks: s.banks || [], sites: targets, batch }) }]).catch(() => {});
      log('⏰ ตั้งเวลา', s.label || s.id, (open ? 'เปิด' : 'ปิด'), s.scope === 'pick' ? (s.banks || []).length + ' ธนาคาร' : 'ทุกธนาคาร', '→', targets.join(','));
    }
  } catch (e) {
    log('⚠️ ตั้งเวลา', e.message);
  } finally { schedRunning = false; }
}

log('🤖 K36 บอทหลังบ้าน v1.0.3 เริ่มทำงาน (K36 + TCG · แก้ช่องทาง + snapshot + เปิด/ปิดธนาคารหลายเว็บ + ตั้งเวลา)');
loop();
setInterval(loop, LOOP_MS);
setInterval(fastLoop, FAST_POLL_MS);
setTimeout(syncLoop, 12 * 1000);   // ซิงค์ครั้งแรกหลังล็อกอินเสร็จ
setInterval(syncLoop, SYNC_MS);
setTimeout(scheduleLoop, 15 * 1000);   // รอให้ล็อกอินเสร็จก่อน
setInterval(scheduleLoop, SCHED_POLL_MS);
setTimeout(sheetWarmLoop, 25 * 1000);  // อุ่นแคชชีตวันนี้ครั้งแรก
setInterval(sheetWarmLoop, 90 * 1000); // แล้วอุ่นทุก 90 วิ

process.on('SIGTERM', () => { log('👋 ปิดบอท'); process.exit(0); });
process.on('unhandledRejection', e => log('⚠️ unhandled:', e && e.message));
