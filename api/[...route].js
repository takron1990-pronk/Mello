// Backend ของ Mello: ทำตามสัญญาที่ index.html เรียกอยู่แล้ว (/api/health /me /register /login /logout /state)
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SESSION_SECRET } = process.env;
const db = SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } }) : null;
const COOKIE = 'mello_session', MAX_AGE = 60 * 60 * 24 * 30;

const sign = (s) => crypto.createHmac('sha256', SESSION_SECRET).update(s).digest('hex');
const hashPw = (pw) => { const salt = crypto.randomBytes(16).toString('hex'); return `${salt}:${crypto.scryptSync(pw, salt, 64).toString('hex')}`; };
const checkPw = (pw, stored) => {
  const [salt, h] = String(stored).split(':');
  const a = Buffer.from(h || '', 'hex'), b = crypto.scryptSync(pw, salt || '', 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const setSession = (res, username) => {
  const body = `${encodeURIComponent(username)}.${Date.now() + MAX_AGE * 1000}`;
  res.setHeader('Set-Cookie', `${COOKIE}=${body}.${sign(body)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${MAX_AGE}`);
};
const clearSession = (res) => res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
const sessionUser = (req) => {
  const m = (req.headers.cookie || '').match(new RegExp(`${COOKIE}=([^;]+)`));
  if (!m) return null;
  const i = m[1].lastIndexOf('.'), body = m[1].slice(0, i), sig = m[1].slice(i + 1);
  const ok = sig.length === 64 && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(sign(body)));
  const [name, exp] = body.split('.');
  return ok && Number(exp) > Date.now() ? decodeURIComponent(name) : null;
};

// รับเฉพาะฟิลด์ความคืบหน้าที่เว็บใช้ และจำกัดชนิด/ขนาด (ไม่เชื่อ body ตรง ๆ)
const num = (v) => (Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), 1e7) : 0);
const list = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string' && x.length < 100).slice(0, 5000) : []);
const cleanState = (b = {}) => ({
  xp_zh: num(b.xp_zh), xp_en: num(b.xp_en),
  completed_zh: list(b.completed_zh), completed_en: list(b.completed_en),
  starred_zh: list(b.starred_zh), starred_en: list(b.starred_en),
  streak: num(b.streak), bestStreak: num(b.bestStreak),
  lastActive: typeof b.lastActive === 'string' ? b.lastActive.slice(0, 40) : null,
  daily: b.daily && typeof b.daily === 'object' && JSON.stringify(b.daily).length < 5000 ? b.daily : null,
});
const toUser = (r) => ({ username: r.username, displayName: r.display_name, createdAt: r.created_at, ...cleanState(r.state) });

module.exports = async (req, res) => {
  const route = new URL(req.url, 'http://x').pathname.replace(/^\/api\/?|\/$/g, '');
  const send = (code, json) => res.status(code).json(json);
  if (route === 'health') return send(200, { ok: !!(db && SESSION_SECRET) });
  if (!db || !SESSION_SECRET) return send(503, { error: 'เซิร์ฟเวอร์ยังไม่ได้ตั้งค่า' });
  const body = req.body && typeof req.body === 'object' ? req.body : {};

  try {
    if (route === 'logout' && req.method === 'POST') { clearSession(res); return send(200, { ok: true }); }

    if ((route === 'register' || route === 'login') && req.method === 'POST') {
      const username = String(body.username || '').trim().toLowerCase();
      const password = String(body.password || '');
      if (!username || username.length > 254 || !password) return send(400, { error: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
      if (route === 'register') {
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(username)) return send(400, { error: 'กรุณากรอกอีเมลให้ถูกต้อง' });
        if (password.length < 6) return send(400, { error: 'รหัสผ่านต้องยาวอย่างน้อย 6 ตัวอักษร' });
        const displayName = String(body.displayName || '').trim().slice(0, 60);
        if (!displayName) return send(400, { error: 'กรุณากรอกชื่อที่ใช้แสดง' });
        const { data, error } = await db.from('mello_users').insert({ username, display_name: displayName, password_hash: hashPw(password), state: cleanState() }).select().single();
        if (error) return send(error.code === '23505' ? 409 : 500, { error: error.code === '23505' ? 'ชื่อผู้ใช้นี้มีในระบบแล้ว' : 'เกิดข้อผิดพลาด กรุณาลองใหม่' });
        setSession(res, username);
        return send(200, { user: toUser(data) });
      }
      const { data } = await db.from('mello_users').select().eq('username', username).maybeSingle();
      if (!data || !checkPw(password, data.password_hash)) return send(401, { error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
      setSession(res, username);
      return send(200, { user: toUser(data) });
    }

    if (route === 'me' || route === 'state') {
      const username = sessionUser(req);
      if (!username) return send(401, { error: 'ยังไม่ได้เข้าสู่ระบบ' });
      if (route === 'state' && req.method === 'PUT') {
        const { data, error } = await db.from('mello_users').update({ state: cleanState(body) }).eq('username', username).select().single();
        if (error) return send(500, { error: 'บันทึกไม่สำเร็จ' });
        return send(200, { user: toUser(data) });
      }
      if (route === 'me' && req.method === 'GET') {
        const { data } = await db.from('mello_users').select().eq('username', username).maybeSingle();
        if (!data) { clearSession(res); return send(401, { error: 'ไม่พบผู้ใช้' }); }
        return send(200, { user: toUser(data) });
      }
    }
    return send(404, { error: 'not found' });
  } catch (e) {
    return send(500, { error: 'เกิดข้อผิดพลาด กรุณาลองใหม่' });
  }
};
