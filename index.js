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
  return { userid: obj.u, password: obj.p };
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
  return h;
}

// ---------- ล็อกอิน ----------
async function login(site, cred) {
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
      s = { token: r.token, exp: r.exp, cipher: site.cred_cipher };
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
  s = { token: r.token, exp: r.exp, cipher: site.cred_cipher };
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

// ========================================================
// ความสามารถของ "ระบบหลังบ้านแบบ K36 (tf6prod-ims)"
// งานช่องทางชำระเงิน: list / get / save
// ========================================================
const VALID_PAYTYPES = ['QR_BANK', 'PROMPTPAY', 'TRUEMONEY', 'DEBIT_CARD', 'USDT'];

// ดึงค่าดิบของช่องทาง: ลอง THB ก่อน ถ้าพังแบบ 499/UNHANDLED (ชั่วคราว) รอแล้วลองสกุลเดิมซ้ำ 1 ครั้ง
// แล้วค่อยลอง USDT ให้; error อื่น (เช่น token) โยนทันที ไม่ไล่สกุลต่อ  — ใช้ร่วมทั้ง get/save (กันเขียนซ้ำ)
async function getRawChannel(site, token, channelId) {
  const cid = encodeURIComponent(channelId);
  let raw, lastErr;
  for (const c of CURRENCIES) {
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
    if (got) break;
  }
  if (raw === undefined) throw lastErr;
  return raw;
}

const K36 = {
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

async function fetchSiteBanks(site, token, currency) {
  const LIMIT = 100, out = [];
  for (let offset = 0; offset < 5000; offset += LIMIT) {
    const q = new URLSearchParams({ offset: String(offset), limit: String(LIMIT), sort: 'ASC', sortcolumn: 'banknameen' });
    if (currency) q.set('currency', currency);
    const res = await boApi(site, token, 'GET', '/banks/search?' + q.toString());
    const rows = Array.isArray(res) ? res : ((res && (res.data || res.list || res.rows || res.content)) || []);
    out.push(...rows);
    const total = res && !Array.isArray(res) ? Number(res.total ?? res.totalCount ?? res.count) : NaN;
    if (rows.length < LIMIT || (isFinite(total) && out.length >= total)) break;
  }
  return out;
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

    // ยิงทีละ 4 ตัว (หลังบ้านเป็น API ทีละแบงก์)
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
    await Promise.all(Array.from({ length: Math.min(4, diff.length) }, worker));

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

const PLATFORMS = { k36: K36, tf6: K36, default: K36 };
function platformOf(site) { return PLATFORMS[site.platform] || PLATFORMS.default; }

// ---------- จัดการคิวงาน bo_tasks ----------
async function claimTask(task) {
  // จองงาน: เปลี่ยน queued→running เฉพาะถ้ายัง queued (กันสองรอบทำซ้ำ)
  const rows = await sb('PATCH',
    `bo_tasks?id=eq.${task.id}&status=eq.queued`,
    { status: 'running', started_at: new Date().toISOString() });
  return true; // Prefer:minimal ไม่คืน rows; เราใช้ if_version ด้วย confirmed อยู่แล้ว
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
  if (a === 'list_site_banks') {
    return await SITE_BANKS.list(site, token, p.currency);
  }
  if (a === 'set_site_banks') {
    if (!task.confirmed) throw new Error('ต้องกดยืนยันก่อนบันทึก');
    const r = await SITE_BANKS.set(site, token, p.banks, p.all, p.currency);
    if (p.batch_id) r.batch_id = p.batch_id;
    return r;
  }
  if (a === 'ping') return { ok: true, name: site.name };
  throw new Error('ไม่รู้จักคำสั่ง: ' + a);
}

async function processTasks(site, token) {
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
    await claimTask(task);
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
    const sites = await sb('GET', 'bo_sites?enabled=eq.true&select=id,name,web_url,api_base,cred_cipher,cipher_fp');
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
  if (fastRunning || running) return; // เลี่ยงชนกับ loop หลัก
  fastRunning = true;
  try {
    const rows = await sb('GET', 'bo_tasks?status=eq.queued&select=site_id&limit=20');
    if (rows && rows.length) {
      // เว็บที่ล็อกอินแล้วเท่านั้น (ที่ยังไม่ล็อกอินปล่อยให้ loop หลักจัดการ)
      const siteIds = [...new Set(rows.map(r => r.site_id))].filter(sid => {
        const s = sessions.get(sid); return s && s.token && fastSiteCache.get(sid);
      });
      // ประมวลผลหลายเว็บ "พร้อมกัน" ทีละ 4 (แต่ละเว็บคนละ session/หลังบ้าน จึงขนานได้)
      const CONC = 4;
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

log('🤖 K36 บอทหลังบ้าน v0.8.0 เริ่มทำงาน (แก้ช่องทาง + snapshot + เปิด/ปิดธนาคารหน้าบ้านหลายเว็บ)');
loop();
setInterval(loop, LOOP_MS);
setInterval(fastLoop, FAST_POLL_MS);
setTimeout(syncLoop, 12 * 1000);   // ซิงค์ครั้งแรกหลังล็อกอินเสร็จ
setInterval(syncLoop, SYNC_MS);

process.on('SIGTERM', () => { log('👋 ปิดบอท'); process.exit(0); });
process.on('unhandledRejection', e => log('⚠️ unhandled:', e && e.message));
