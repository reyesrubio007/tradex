
// TradeX v0.9 — full app
// Features:
//  • Multi-user (admin/user), per-user trades
//  • SQLite session store (connect-sqlite3)
//  • Dashboard with Calendar PnL, daily/weekly/monthly summaries
//  • CSV import (flexible headers)
//  • Admin panel (add/delete users, can’t delete last admin)
//  • Password reset (/reset-password) guarded by RESET_TOKEN
//  • Bootstrap new admin (/bootstrap-admin) guarded by RESET_TOKEN — with detailed errors
//  • Diagnostics page /_diag
//
// ENV (Render):
//  DB_PATH=/var/data/journal.db
//  SESSIONS_DIR=/var/data
//  SESSION_SECRET=<long_random>
//  NODE_VERSION=20
//  RESET_TOKEN=<temporary when needed, then remove>
//
// Install locally:
//  npm i express sqlite3 multer csv-parse express-session connect-sqlite3 bcryptjs
//  node server.js  → http://localhost:3000

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const { parse } = require('csv-parse');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;
const APP_NAME = 'TradeX';

// ---- Favicon / branding ----
const FAVICON_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="12" fill="#0f172a"/>
  <path d="M16 40 L28 26 L36 34 L48 20" stroke="#10b981" stroke-width="6" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="48" cy="20" r="3" fill="#10b981"/>
</svg>`;
app.get('/favicon.ico', (req, res) => res.type('image/svg+xml').send(FAVICON_SVG));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ---- DB ----
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'journal.db');
const db = new sqlite3.Database(DB_PATH);
const dbAll = (sql, p = []) => new Promise((res, rej) => db.all(sql, p, (e, r) => e ? rej(e) : res(r)));
const dbGet = (sql, p = []) => new Promise((res, rej) => db.get(sql, p, (e, r) => e ? rej(e) : res(r)));
const dbRun = (sql, p = []) => new Promise((res, rej) => db.run(sql, p, function (e) { e ? rej(e) : res({ changes: this.changes, lastID: this.lastID }); }));

async function ensureSchema() {
  await dbRun(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS trades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trade_date TEXT NOT NULL,
    symbol TEXT NOT NULL,
    side TEXT NOT NULL CHECK(side IN ('LONG','SHORT')),
    qty INTEGER NOT NULL,
    entry_price REAL NOT NULL,
    exit_price REAL NOT NULL,
    fees REAL NOT NULL DEFAULT 0,
    notes TEXT
  )`);
  // add user_id if missing; assign existing trades to earliest user
  const cols = await dbAll(`PRAGMA table_info(trades)`);
  if (!cols.find(c => c.name === 'user_id')) {
    await dbRun(`ALTER TABLE trades ADD COLUMN user_id INTEGER`);
    const firstUser = await dbGet(`SELECT id FROM users ORDER BY id ASC LIMIT 1`);
    if (firstUser) await dbRun(`UPDATE trades SET user_id = ? WHERE user_id IS NULL`, [firstUser.id]);
  }
}

// ---- Sessions (SQLite store) ----
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_only_change_me_please_1234567890';
const sessionsDir = process.env.SESSIONS_DIR || path.dirname(DB_PATH);

app.use(session({
  name: 'tradex.sid',
  secret: SESSION_SECRET,
  store: new SQLiteStore({
    dir: sessionsDir,
    db: 'sessions.db',
    concurrentDB: false
  }),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: !!process.env.RENDER,
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

// ---- Utils ----
const esc = s => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\\"/g, '&quot;').replace(/'/g, '&#039;');
const isValidDate = s => /^\d{4}-\d{2}-\d{2}$/.test(s);
const toNum = (x, d = 0) => { const n = parseFloat(x); return Number.isFinite(n) ? n : d; };
const computePnl = r => {
  const g = r.side === 'LONG'
    ? (r.exit_price - r.entry_price) * r.qty
    : (r.entry_price - r.exit_price) * r.qty;
  return g - (r.fees || 0);
};
const currency = n => { const v = Number(n || 0); const s = v.toFixed(2); return v >= 0 ? ('$' + s) : ('-$' + Math.abs(v).toFixed(2)); };
function isoWeekKey(s) {
  const [Y, M, D] = s.split('-').map(Number);
  const d = new Date(Date.UTC(Y, M - 1, D));
  const day = (d.getUTCDay() + 6) % 7;
  const th = new Date(d); th.setUTCDate(d.getUTCDate() - day + 3);
  const wy = th.getUTCFullYear();
  const jan4 = new Date(Date.UTC(wy, 0, 4));
  const jday = (jan4.getUTCDay() + 6) % 7;
  const w1 = new Date(jan4); w1.setUTCDate(jan4.getUTCDate() - jday);
  const w = 1 + Math.round((d - w1) / (7 * 24 * 3600 * 1000));
  return `${wy}-W${String(w).padStart(2, '0')}`;
}

// ---- Auth guards ----
function requireAuth(req, res, next) { if (req.session && req.session.user) return next(); return res.redirect('/login'); }
function requireAdmin(req, res, next) { if (req.session && req.session.user && req.session.user.role === 'admin') return next(); return res.status(403).send('Admins only'); }

// ---- Auth routes ----
app.get('/login', async (req, res) => {
  const c = await dbGet(`SELECT COUNT(*) AS c FROM users`);
  const canSignup = (c && c.c === 0);
  const err = req.query.err ? `<div style="color:#b91c1c">${esc(req.query.err)}</div>` : '';
  res.send(`<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>${APP_NAME} • Login</title><script src='https://cdn.tailwindcss.com'></script></head><body class='bg-slate-50 text-slate-900'><div class='max-w-md mx-auto p-6 mt-10 bg-white rounded-2xl shadow'><h1 class='text-2xl font-bold mb-4 text-center'>${APP_NAME} — Login</h1>${err}<form method='POST' action='/login' class='space-y-3'><div><label class='block text-xs text-slate-600'>Email</label><input name='email' type='email' required class='w-full border rounded-xl p-2'></div><div><label class='block text-xs text-slate-600'>Password</label><input name='password' type='password' required class='w-full border rounded-xl p-2'></div><button class='w-full px-4 py-2 rounded-xl shadow bg-slate-900 text-white'>Sign in</button></form>${canSignup ? "<p class='text-xs text-slate-500 mt-3 text-center'>First time here? <a class='underline' href='/signup'>Create the first admin</a></p>" : ""}</div></body></html>`);
});

app.post('/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const pass = String(req.body.password || '');
    const u = await dbGet(`SELECT * FROM users WHERE email=?`, [email]);
    if (!u) return res.redirect('/login?err=' + encodeURIComponent('Invalid email or password'));
    const ok = await bcrypt.compare(pass, u.password_hash);
    if (!ok) return res.redirect('/login?err=' + encodeURIComponent('Invalid email or password'));
    req.session.user = { id: u.id, email: u.email, role: u.role };
    res.redirect('/');
  } catch (e) { console.error(e); res.redirect('/login?err=' + encodeURIComponent('Login error')); }
});

app.get('/signup', async (req, res) => {
  const c = await dbGet(`SELECT COUNT(*) AS c FROM users`);
  if (!c || c.c !== 0) return res.redirect('/login');
  res.send(`<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>${APP_NAME} • Create Admin</title><script src='https://cdn.tailwindcss.com'></script></head><body class='bg-slate-50 text-slate-900'><div class='max-w-md mx-auto p-6 mt-10 bg-white rounded-2xl shadow'><h1 class='text-2xl font-bold mb-4 text-center'>${APP_NAME} — First Admin</h1><form method='POST' action='/signup' class='space-y-3'><div><label class='block text-xs text-slate-600'>Email</label><input name='email' type='email' required class='w-full border rounded-xl p-2'></div><div><label class='block text-xs text-slate-600'>Password</label><input name='password' type='password' minlength='6' required class='w-full border rounded-xl p-2'></div><button class='w-full px-4 py-2 rounded-xl shadow bg-slate-900 text-white'>Create Admin</button></form></div></body></html>`);
});

app.post('/signup', async (req, res) => {
  try {
    const c = await dbGet(`SELECT COUNT(*) AS c FROM users`);
    if (!c || c.c !== 0) return res.redirect('/login');
    const email = String(req.body.email || '').trim().toLowerCase();
    const pass = String(req.body.password || '');
    if (!email || pass.length < 6) return res.redirect('/signup?err=' + encodeURIComponent('Invalid email or short password'));
    const hash = await bcrypt.hash(pass, 10);
    await dbRun(`INSERT INTO users(email,password_hash,role) VALUES(?,?, 'admin')`, [email, hash]);
    res.redirect('/login');
  } catch (e) { console.error(e); res.redirect('/signup?err=' + encodeURIComponent('Signup error')); }
});

app.post('/logout', (req, res) => { req.session.destroy(() => res.redirect('/login')); });

// ---- Admin: users ----
app.get('/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const users = await dbAll(`SELECT id,email,role,created_at FROM users ORDER BY id ASC`);
  const err = req.query.err ? `<div class='mb-2 text-rose-600 text-sm'>${esc(req.query.err)}</div>` : '';
  const ok = req.query.ok ? `<div class='mb-2 text-emerald-600 text-sm'>${esc(req.query.ok)}</div>` : '';
  res.send(`<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>${APP_NAME} • Users</title><script src='https://cdn.tailwindcss.com'></script></head><body class='bg-slate-50 text-slate-900'><div class='max-w-3xl mx-auto p-6 space-y-4'><div class='flex items-center justify-between'><h1 class='text-2xl font-bold'>Users</h1><a class='underline' href='/'>Back</a></div>${err}${ok}<div class='bg-white rounded-2xl shadow p-4'><form method='POST' action='/admin/users' class='grid md:grid-cols-4 gap-3'><input name='email' type='email' placeholder='email@example.com' required class='border rounded-xl p-2 md:col-span-2'><input name='password' type='password' placeholder='password (min 6)' minlength='6' required class='border rounded-xl p-2'><select name='role' class='border rounded-xl p-2'><option value='user'>user</option><option value='admin'>admin</option></select><button class='px-4 py-2 rounded-xl shadow bg-slate-900 text-white md:col-span-1'>Add user</button></form></div><div class='bg-white rounded-2xl shadow p-4'><table class='min-w-full text-sm'><thead><tr class='text-left border-b'><th class='py-2 pr-4'>ID</th><th class='py-2 pr-4'>Email</th><th class='py-2 pr-4'>Role</th><th class='py-2'>Actions</th></tr></thead><tbody>${users.map(u => `<tr class='border-b last:border-b-0'><td class='py-2 pr-4'>${u.id}</td><td class='py-2 pr-4'>${esc(u.email)}</td><td class='py-2 pr-4'>${u.role}</td><td class='py-2'>${u.id === req.session.user.id ? '<span class="text-slate-400">(you)</span>' : `<form method='POST' action='/admin/users/${u.id}/delete' onsubmit='return confirm("Delete user ${esc(u.email)}?");'><button class='underline text-rose-700'>Delete</button></form>`}</td></tr>`).join('')}</tbody></table></div></div></body></html>`);
});

app.post('/admin/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const pass = String(req.body.password || '');
    const role = (req.body.role === 'admin') ? 'admin' : 'user';
    if (!email || pass.length < 6) return res.redirect('/admin/users?err=' + encodeURIComponent('Invalid email or short password'));
    const hash = await bcrypt.hash(pass, 10);
    await dbRun(`INSERT INTO users(email,password_hash,role) VALUES(?,?,?)`, [email, hash, role]);
    res.redirect('/admin/users?ok=' + encodeURIComponent('User created'));
  } catch (e) { console.error(e); res.redirect('/admin/users?err=' + encodeURIComponent('Error creating user')); }
});

app.post('/admin/users/:id/delete', requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (id === req.session.user.id) return res.redirect('/admin/users?err=' + encodeURIComponent("You can't delete yourself"));
    const admins = await dbGet(`SELECT COUNT(*) AS c FROM users WHERE role='admin'`);
    const victim = await dbGet(`SELECT role FROM users WHERE id=?`, [id]);
    if (victim && victim.role === 'admin' && admins && admins.c <= 1) return res.redirect('/admin/users?err=' + encodeURIComponent('At least one admin required'));
    await dbRun(`DELETE FROM users WHERE id=?`, [id]);
    res.redirect('/admin/users?ok=' + encodeURIComponent('User deleted'));
  } catch (e) { console.error(e); res.redirect('/admin/users?err=' + encodeURIComponent('Error deleting user')); }
});

// ---- CSV Upload ----
const upload = multer({ dest: path.join(__dirname, 'uploads') });
const normalizeDate = s => {
  if (!s) return null;
  s = String(s).trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  const m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{2,4})$/);
  if (m) { let mm = +m[1], dd = +m[2], yy = +m[3]; if (yy < 100) yy += 2000; return `${yy}-${String(mm).padStart(2, '0')}-${String(dd).padStart(2, '0')}`; }
  return null;
};
const normalizeSide = s => { s = String(s || '').trim().toUpperCase(); return s.startsWith('S') ? 'SHORT' : 'LONG'; };

// ---- Dashboard (per-user) ----
app.get('/', requireAuth, async (req, res) => {
  try {
    const uid = req.session.user.id;
    const now = new Date();
    const y = parseInt(req.query.y || now.getUTCFullYear());
    const m = parseInt(req.query.m || now.getUTCMonth() + 1);
    const year = Math.max(1970, Math.min(3000, y));
    const monthIdx = Math.max(0, Math.min(11, m - 1));

    const trades = await dbAll(`SELECT id,trade_date,symbol,side,qty,entry_price,exit_price,fees,notes FROM trades WHERE user_id=? ORDER BY trade_date DESC,id DESC`, [uid]);
    const withPnL = trades.map(t => ({ ...t, pnl: computePnl(t) }));

    const dailyMap = new Map();
    for (const t of withPnL) dailyMap.set(t.trade_date, (dailyMap.get(t.trade_date) || 0) + t.pnl);
    const dailySorted = Array.from(dailyMap.entries()).sort((a, b) => a[0].localeCompare(b[0])).map(([date, total]) => ({ date, total }));

    const totalTrades = withPnL.length;
    const winners = withPnL.filter(t => t.pnl > 0);
    const losers = withPnL.filter(t => t.pnl < 0);
    const grossPnL = withPnL.reduce((a, b) => a + b.pnl, 0);
    const winRate = totalTrades ? (winners.length / totalTrades) * 100 : 0;
    const avgWin = winners.length ? winners.reduce((a, b) => a + b.pnl, 0) / winners.length : 0;
    const avgLoss = losers.length ? Math.abs(losers.reduce((a, b) => a + b.pnl, 0) / losers.length) : 0;
    const expectancy = (winRate / 100) * avgWin - (1 - winRate / 100) * avgLoss;

    const monthStr = `${year}-${String(monthIdx + 1).padStart(2, '0')}`;
    const mtdDaily = dailySorted.filter(d => d.date.startsWith(monthStr));
    const mtdPnL = mtdDaily.reduce((a, b) => a + b.total, 0);
    const bestDay = dailySorted.length ? dailySorted.reduce((best, d) => d.total > best.total ? d : best, { total: -Infinity }) : null;
    const worstDay = dailySorted.length ? dailySorted.reduce((wst, d) => d.total < wst.total ? d : wst, { total: Infinity }) : null;

    const weekly = new Map(), monthly = new Map();
    for (const d of dailySorted) { const wk = isoWeekKey(d.date); weekly.set(wk, (weekly.get(wk) || 0) + d.total); const mk = d.date.slice(0, 7); monthly.set(mk, (monthly.get(mk) || 0) + d.total); }
    const weeklySummary = Array.from(weekly.entries()).sort((a, b) => a[0].localeCompare(b[0])).map(([week, total]) => ({ week, total }));
    const monthlySummary = Array.from(monthly.entries()).sort((a, b) => a[0].localeCompare(b[0])).map(([month, total]) => ({ month, total }));

    // Calendar grid
    const first = new Date(Date.UTC(year, monthIdx, 1));
    const last = new Date(Date.UTC(year, monthIdx + 1, 0));
    const dim = last.getUTCDate();
    const fdow = first.getUTCDay();
    const cells = [];
    for (let i = 0; i < fdow; i++) cells.push(null);
    for (let day = 1; day <= dim; day++) {
      const ds = `${year}-${String(monthIdx + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
      const pnl = dailyMap.get(ds) || 0;
      cells.push({ ds, day, pnl });
    }
    while (cells.length % 7 !== 0) cells.push(null);
    const weeks = []; for (let i = 0; i < cells.length; i += 7) weeks.push(cells.slice(i, i + 7));

    const prev = new Date(Date.UTC(year, monthIdx - 1, 1));
    const next = new Date(Date.UTC(year, monthIdx + 1, 1));
    const prevLink = `/?y=${prev.getUTCFullYear()}&m=${prev.getUTCMonth() + 1}`;
    const nextLink = `/?y=${next.getUTCFullYear()}&m=${next.getUTCMonth() + 1}`;

    const weekdayHeader = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map(d => `<div class='text-center'>${d}</div>`).join('');
    const calendarGrid = weeks.map(week => week.map(c => {
      if (!c) return "<div class='h-20 rounded-xl bg-slate-100'></div>";
      const pnl = +c.pnl;
      const cls = pnl > 0 ? 'bg-emerald-200' : (pnl < 0 ? 'bg-rose-200' : 'bg-slate-100');
      const tone = pnl > 0 ? 'text-emerald-700' : (pnl < 0 ? 'text-rose-700' : 'text-slate-500');
      const txt = pnl ? ((pnl >= 0 ? '+' : '') + pnl.toFixed(2)) : '';
      return `<div class='h-20 rounded-xl ${cls} p-2 flex flex-col justify-between'><div class='text-[10px] text-slate-600'>${c.ds}</div><div class='text-right text-sm font-mono ${tone}'>${txt}</div></div>`;
    }).join('')).join('');

    function metric(title, val, raw) { const tone = typeof raw === 'number' ? (raw > 0 ? 'text-emerald-600' : raw < 0 ? 'text-rose-600' : '') : ''; return `<div class='bg-white rounded-2xl shadow p-5'><div class='text-xs text-slate-500'>${title}</div><div class='text-2xl font-semibold mt-1 ${tone}'>${val}</div></div>`; }

    const html = `<!doctype html><html lang='en'><head><meta charset='utf-8'/><meta name='viewport' content='width=device-width, initial-scale=1'/><title>${APP_NAME} • Dashboard</title><link rel='icon' href='/favicon.ico'><script src='https://cdn.tailwindcss.com'></script><script src='https://cdn.jsdelivr.net/npm/chart.js'></script></head><body class='bg-slate-50 text-slate-900'><div class='max-w-7xl mx-auto p-6 space-y-6'><header class='flex items-center justify-between'><h1 class='text-2xl md:text-3xl font-bold'>${APP_NAME}</h1><nav class='flex items-center gap-4 text-sm'>${req.session.user.role === 'admin' ? "<a class='underline' href='/admin/users'>Users</a>" : ""}<a class='underline' href='/about'>About</a><form method='POST' action='/logout'><button class='underline text-rose-700'>Logout (${esc(req.session.user.email)})</button></form></nav></header><section class='grid md:grid-cols-4 gap-4'>${metric('Total Trades', String(totalTrades))}${metric('Win Rate', winRate.toFixed(1) + '%')}${metric('Gross PnL', currency(grossPnL), grossPnL)}${metric('Expectancy/trade', currency(expectancy), expectancy)}</section><section class='grid lg:grid-cols-3 gap-6'><div class='lg:col-span-2 bg-white rounded-2xl shadow p-5'><div class='flex items-center justify-between mb-3'><h2 class='text-xl font-semibold'>Calendar PnL — ${year}-${String(monthIdx + 1).padStart(2, '0')}</h2><div class='flex items-center gap-2'><a class='px-3 py-1 rounded-xl border' href='${prevLink}'>◀ Prev</a><a class='px-3 py-1 rounded-xl border' href='${nextLink}'>Next ▶</a></div></div><div class='grid grid-cols-7 text-xs text-slate-500 mb-2'>${weekdayHeader}</div><div class='grid grid-cols-7 gap-2'>${calendarGrid}</div></div><div class='bg-white rounded-2xl shadow p-5'><h2 class='text-xl font-semibold mb-3'>MTD & Highlights</h2><ul class='text-sm space-y-2'><li><span class='text-slate-500'>Month-to-date PnL:</span> <span class='font-mono ${mtdPnL >= 0 ? 'text-emerald-600' : 'text-rose-600'}'>${currency(mtdPnL)}</span></li><li><span class='text-slate-500'>Best day:</span> ${bestDay ? `${bestDay.date} — <span class='font-mono text-emerald-600'>${currency(bestDay.total)}</span>` : '—'}</li><li><span class='text-slate-500'>Worst day:</span> ${worstDay ? `${worstDay.date} — <span class='font-mono text-rose-600'>${currency(worstDay.total)}</span>` : '—'}</li></ul><div class='mt-4'><canvas id='pnlChart' height='130'></canvas></div></div></section><section class='grid lg:grid-cols-3 gap-6'><div class='bg-white rounded-2xl shadow p-5'><h2 class='text-xl font-semibold mb-3'>Weekly PnL (ISO weeks)</h2><div class='overflow-x-auto'><table class='min-w-full text-sm'><thead><tr class='text-left border-b'><th class='py-2 pr-4'>Week</th><th class='py-2'>Total</th></tr></thead><tbody>${weeklySummary.length ? weeklySummary.map(w => `<tr class='border-b last:border-b-0'><td class='py-2 pr-4'>${w.week}</td><td class='py-2 font-mono ${w.total >= 0 ? 'text-emerald-600' : 'text-rose-600'}'>${w.total.toFixed(2)}</td></tr>`).join('') : `<tr><td class='py-2' colspan='2'>No data yet.</td></tr>`}</tbody></table></div></div><div class='bg-white rounded-2xl shadow p-5'><h2 class='text-xl font-semibold mb-3'>Monthly PnL</h2><div class='overflow-x-auto'><table class='min-w-full text-sm'><thead><tr class='text-left border-b'><th class='py-2 pr-4'>Month</th><th class='py-2'>Total</th></tr></thead><tbody>${monthlySummary.length ? monthlySummary.map(m => `<tr class='border-b last:border-b-0'><td class='py-2 pr-4'>${m.month}</td><td class='py-2 font-mono ${m.total >= 0 ? 'text-emerald-600' : 'text-rose-600'}'>${m.total.toFixed(2)}</td></tr>`).join('') : `<tr><td class='py-2' colspan='2'>No data yet.</td></tr>`}</tbody></table></div></div><div class='bg-white rounded-2xl shadow p-5'><h2 class='text-xl font-semibold mb-3'>CSV Import</h2><form method='POST' action='/import' enctype='multipart/form-data' class='space-y-3'><input type='file' name='csvfile' accept='.csv' class='block w-full text-sm'><button class='px-4 py-2 rounded-xl shadow bg-slate-900 text-white'>Upload & Import</button></form><p class='text-xs text-slate-500 mt-3'>Accepted: date/trade_date, symbol, side, qty, entry, exit, fees, notes.</p></div></section><section class='grid md:grid-cols-2 gap-6'><div id='add' class='bg-white rounded-2xl shadow p-5'><h2 class='text-xl font-semibold mb-3'>Add Trade</h2><form method='POST' action='/trades' class='grid grid-cols-2 gap-3'><div class='col-span-2'><label class='block text-xs text-slate-600'>Date</label><input name='trade_date' type='date' required class='w-full border rounded-xl p-2'></div><div><label class='block text-xs text-slate-600'>Symbol</label><input name='symbol' required class='w-full border rounded-xl p-2'></div><div><label class='block text-xs text-slate-600'>Side</label><select name='side' class='w-full border rounded-xl p-2'><option>LONG</option><option>SHORT</option></select></div><div><label class='block text-xs text-slate-600'>Qty</label><input name='qty' type='number' min='1' value='1' required class='w-full border rounded-xl p-2'></div><div><label class='block text-xs text-slate-600'>Entry</label><input name='entry_price' type='number' step='0.01' required class='w-full border rounded-xl p-2'></div><div><label class='block text-xs text-slate-600'>Exit</label><input name='exit_price' type='number' step='0.01' required class='w-full border rounded-xl p-2'></div><div class='col-span-2'><label class='block text-xs text-slate-600'>Fees</label><input name='fees' type='number' step='0.01' value='0' class='w-full border rounded-xl p-2'></div><div class='col-span-2'><label class='block text-xs text-slate-600'>Notes</label><textarea name='notes' rows='2' class='w-full border rounded-xl p-2'></textarea></div><div class='col-span-2 flex gap-2'><button class='px-4 py-2 rounded-xl shadow bg-slate-900 text-white'>Save</button><a href='/' class='px-4 py-2 rounded-xl border'>Cancel</a></div></form></div><div class='bg-white rounded-2xl shadow p-5'><h2 class='text-xl font-semibold mb-3'>Daily PnL</h2><div class='overflow-x-auto'><table class='min-w-full text-sm'><thead><tr class='text-left border-b'><th class='py-2 pr-4'>Date</th><th class='py-2'>Total PnL</th></tr></thead><tbody>${dailySorted.length ? dailySorted.map(d => `<tr class='border-b last:border-b-0'><td class='py-2 pr-4'>${d.date}</td><td class='py-2 font-mono ${d.total >= 0 ? 'text-emerald-600' : 'text-rose-600'}'>${d.total.toFixed(2)}</td></tr>`).join('') : `<tr><td class='py-2' colspan='2'>No data yet.</td></tr>`}</tbody></table></div></div></section><section class='bg-white rounded-2xl shadow p-5'><h2 class='text-xl font-semibold mb-3'>Trades</h2><div class='overflow-x-auto'><table class='min-w-full text-sm'><thead><tr class='text-left border-b'><th class='py-2 pr-4'>Date</th><th class='py-2 pr-4'>Symbol</th><th class='py-2 pr-4'>Side</th><th class='py-2 pr-4'>Qty</th><th class='py-2 pr-4'>Entry</th><th class='py-2 pr-4'>Exit</th><th class='py-2 pr-4'>Fees</th><th class='py-2 pr-4'>PnL</th><th class='py-2 pr-4'>Notes</th><th class='py-2'>Actions</th></tr></thead><tbody>${withPnL.length ? withPnL.map(t => `<tr class='border-b last:border-b-0 align-top'><td class='py-2 pr-4'>${t.trade_date}</td><td class='py-2 pr-4 font-mono'>${t.symbol}</td><td class='py-2 pr-4'>${t.side}</td><td class='py-2 pr-4'>${t.qty}</td><td class='py-2 pr-4'>${Number(t.entry_price).toFixed(2)}</td><td class='py-2 pr-4'>${Number(t.exit_price).toFixed(2)}</td><td class='py-2 pr-4'>${Number(t.fees || 0).toFixed(2)}</td><td class='py-2 pr-4 font-mono ${t.pnl >= 0 ? 'text-emerald-600' : 'text-rose-600'}'>${t.pnl.toFixed(2)}</td><td class='py-2 pr-4 whitespace-pre-wrap'>${t.notes ? esc(t.notes) : ''}</td><td class='py-2'><form method='POST' action='/trades/${t.id}/delete' onsubmit='return confirm("Delete this trade?");'><button class='text-rose-700 underline'>Delete</button></form></td></tr>`).join('') : `<tr><td class='py-2' colspan='10'>No trades yet. Add your first trade above.</td></tr>`}</tbody></table></div></section><footer class='text-xs text-slate-500 text-center py-6'>${APP_NAME} • v0.9</footer></div><script>const labels=${JSON.stringify(dailySorted.map(d => d.date))}; const data=${JSON.stringify(dailySorted.map(d => +d.total.toFixed(2)))}; const ctx=document.getElementById('pnlChart'); if(ctx&&labels.length){ new Chart(ctx,{type:'bar',data:{labels,datasets:[{label:'Daily PnL',data}]},options:{responsive:true,scales:{y:{beginAtZero:true}}}}); }</script></body></html>`;
    res.status(200).send(html);
  } catch (err) { console.error(err); res.status(500).send('Server error'); }
});

// ---- Trade mutations (per-user) ----
app.post('/trades', requireAuth, async (req, res) => {
  try {
    const uid = req.session.user.id;
    const { trade_date, symbol, side, qty, entry_price, exit_price, fees = 0, notes = '' } = req.body;
    if (!isValidDate(trade_date)) throw new Error('Invalid date');
    if (!symbol || (side !== 'LONG' && side !== 'SHORT')) throw new Error('Invalid symbol/side');
    const qtyNum = parseInt(qty, 10); const entry = toNum(entry_price); const exit = toNum(exit_price); const fee = toNum(fees, 0);
    if (!(qtyNum > 0) || !Number.isFinite(entry) || !Number.isFinite(exit)) throw new Error('Invalid numbers');
    await dbRun(`INSERT INTO trades (trade_date,symbol,side,qty,entry_price,exit_price,fees,notes,user_id) VALUES (?,?,?,?,?,?,?,?,?)`,
      [trade_date, symbol.trim().toUpperCase(), side, qtyNum, entry, exit, fee, notes, uid]);
    res.redirect('back');
  } catch (e) { console.error(e); res.status(400).send('Bad request: ' + e.message); }
});

app.post('/trades/:id/delete', requireAuth, async (req, res) => {
  try { const uid = req.session.user.id; const id = parseInt(req.params.id, 10); if (!id) throw new Error('Invalid ID'); await dbRun(`DELETE FROM trades WHERE id=? AND user_id=?`, [id, uid]); res.redirect('back'); }
  catch (e) { console.error(e); res.status(400).send('Bad request: ' + e.message); }
});

// ---- CSV Import ----
app.post('/import', requireAuth, upload.single('csvfile'), async (req, res) => {
  if (!req.file) return res.status(400).send('No file');
  const uid = req.session.user.id; const filePath = req.file.path; const rows = [];
  try {
    await new Promise((resolve, reject) => {
      fs.createReadStream(filePath).pipe(parse({ columns: true, skip_empty_lines: true, trim: true }))
        .on('data', r => rows.push(r)).on('end', resolve).on('error', reject);
    });
    let inserted = 0, skipped = 0;
    for (const r of rows) {
      const trade_date = normalizeDate(r.date || r.trade_date || r.TradeDate || r['Trade Date'] || r['Date']);
      const symbol = (r.symbol || r.Symbol || r.ticker || r.Ticker || '').toString().trim().toUpperCase();
      const side = normalizeSide(r.side || r.Side || r.direction || r.Direction);
      const qty = toNum(r.qty || r.Quantity || r.contracts || r.size, 0);
      const entry_price = toNum(r.entry || r.Entry || r.entry_price || r['Entry Price'] || r.avg_entry || r['Avg Entry']);
      const exit_price = toNum(r.exit || r.Exit || r.exit_price || r['Exit Price'] || r.avg_exit || r['Avg Exit']);
      const fees = toNum(r.fees || r.Fees || r.commissions || r.Commissions || r['Commission'], 0);
      const notes = (r.notes || r.Notes || r.strategy || r.Strategy || '').toString();
      if (!trade_date || !symbol || !(qty > 0) || !Number.isFinite(entry_price) || !Number.isFinite(exit_price)) { skipped++; continue; }
      await dbRun(`INSERT INTO trades (trade_date,symbol,side,qty,entry_price,exit_price,fees,notes,user_id) VALUES (?,?,?,?,?,?,?,?,?)`, [trade_date, symbol, side, qty, entry_price, exit_price, fees, notes, uid]);
      inserted++;
    }
    res.redirect(`/?imported=${inserted}&skipped=${skipped}`);
  } catch (e) { console.error(e); res.status(500).send('Import error: ' + e.message); }
  finally { fs.unlink(filePath, () => { }); }
});

// ---- Simple APIs (per-user) ----
app.get('/api/trades', requireAuth, async (req, res) => {
  try { const uid = req.session.user.id; const rows = await dbAll(`SELECT * FROM trades WHERE user_id=? ORDER BY trade_date DESC,id DESC`, [uid]); res.json(rows.map(r => ({ ...r, pnl: computePnl(r) }))); } catch (e) { res.status(500).json({ error: 'Server error' }); }
});
app.get('/api/daily-pnl', requireAuth, async (req, res) => {
  try { const uid = req.session.user.id; const rows = await dbAll(`SELECT trade_date, SUM(CASE WHEN side='LONG' THEN (exit_price-entry_price)*qty WHEN side='SHORT' THEN (entry_price-exit_price)*qty END - fees) AS total FROM trades WHERE user_id=? GROUP BY trade_date ORDER BY trade_date`, [uid]); res.json(rows); } catch (e) { res.status(500).json({ error: 'Server error' }); }
});
app.get('/api/weekly-pnl', requireAuth, async (req, res) => {
  try { const uid = req.session.user.id; const rows = await dbAll(`SELECT trade_date, SUM(CASE WHEN side='LONG' THEN (exit_price-entry_price)*qty WHEN side='SHORT' THEN (entry_price-exit_price)*qty END - fees) AS total FROM trades WHERE user_id=? GROUP BY trade_date ORDER BY trade_date`, [uid]); const weekly = {}; for (const r of rows) { const k = isoWeekKey(r.trade_date); weekly[k] = (weekly[k] || 0) + (r.total || 0); } res.json(Object.entries(weekly).sort((a, b) => a[0].localeCompare(b[0])).map(([week, total]) => ({ week, total }))); } catch (e) { res.status(500).json({ error: 'Server error' }); }
});
app.get('/api/monthly-pnl', requireAuth, async (req, res) => {
  try { const uid = req.session.user.id; const rows = await dbAll(`SELECT trade_date, SUM(CASE WHEN side='LONG' THEN (exit_price-entry_price)*qty WHEN side='SHORT' THEN (entry_price-exit_price)*qty END - fees) AS total FROM trades WHERE user_id=? GROUP BY trade_date ORDER BY trade_date`, [uid]); const monthly = {}; for (const r of rows) { const k = r.trade_date.slice(0, 7); monthly[k] = (monthly[k] || 0) + (r.total || 0); } res.json(Object.entries(monthly).sort((a, b) => a[0].localeCompare(b[0])).map(([month, total]) => ({ month, total }))); } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ---- About (public) ----
app.get('/about', (_req, res) => {
  res.send(`<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>${APP_NAME} • About</title><script src='https://cdn.tailwindcss.com'></script></head><body class='bg-slate-50 text-slate-900'><div class='max-w-3xl mx-auto p-6 space-y-4'><a href='/' class='text-sm underline'>&larr; Back</a><h1 class='text-3xl font-bold'>${APP_NAME}</h1><p class='text-slate-600'>Multi-user trade journal with Calendar PnL, CSV import, summaries, and login.</p><p class='text-xs text-slate-500'>© ${new Date().getFullYear()} Reyes</p></div></body></html>`);
});

// ---- Token-protected helpers ----
app.get('/reset-password', (req, res) => {
  if (!process.env.RESET_TOKEN) return res.status(404).send('Not enabled');
  res.send(`<h1>Password Reset</h1>
    <form method="POST">
      <input name=email placeholder="email" required>
      <input name=password type="password" placeholder="new password (min 6)" minlength="6" required>
      <input name=token placeholder="RESET_TOKEN" required>
      <button>Reset</button>
    </form>`);
});

app.post('/reset-password', async (req, res) => {
  try {
    const token = String(req.body.token || '');
    if (!process.env.RESET_TOKEN || token !== process.env.RESET_TOKEN) {
      return res.status(403).send('Bad token');
    }
    const email = String(req.body.email || '').trim().toLowerCase();
    const pass = String(req.body.password || '');
    if (!email || pass.length < 6) return res.status(400).send('Invalid input');
    const hash = await bcrypt.hash(pass, 10);
    const r = await dbRun(`UPDATE users SET password_hash=? WHERE email=?`, [hash, email]);
    if (!r.changes) return res.status(404).send('User not found');
    res.send('Password updated. <a href="/login">Go to login</a>');
  } catch (e) { console.error(e); res.status(500).send('Reset error'); }
});

// --- Bootstrap admin (debuggable) ---
app.get('/bootstrap-admin', (req, res) => {
  if (!process.env.RESET_TOKEN) return res.status(404).send('Not enabled');
  res.send(`<h1>Create Admin</h1>
    <form method="POST" action="/bootstrap-admin" style="display:grid;gap:8px;max-width:360px;">
      <input name="email" type="email" placeholder="email" required>
      <input name="password" type="password" placeholder="password (min 6)" minlength="6" required>
      <input name="token" placeholder="RESET_TOKEN" required>
      <button>Create Admin</button>
    </form>`);
});

app.post('/bootstrap-admin', async (req, res) => {
  try {
    if (!process.env.RESET_TOKEN || req.body.token !== process.env.RESET_TOKEN) {
      return res.status(403).send('Bootstrap error: Bad token (RESET_TOKEN mismatch or not set)');
    }
    const email = String(req.body.email || '').trim().toLowerCase();
    const pass = String(req.body.password || '');
    if (!email) return res.status(400).send('Bootstrap error: Missing email');
    if (pass.length < 6) return res.status(400).send('Bootstrap error: Password too short');

    const exists = await dbGet(`SELECT id FROM users WHERE email=?`, [email]);
    if (exists) return res.status(409).send('Bootstrap error: Email already exists. Use /reset-password instead.');

    const hash = await bcrypt.hash(pass, 10);
    await dbRun(`INSERT INTO users(email, password_hash, role) VALUES(?, ?, 'admin')`, [email, hash]);

    res.send('Admin created. <a href="/login">Log in</a>');
  } catch (e) {
    console.error(e);
    res.status(500).send('Bootstrap error: ' + (e && e.message ? e.message : String(e)));
  }
});

// ---- Diagnostics (helps verify env/users quickly) ----
app.get('/_diag', async (req, res) => {
  const env = {
    DB_PATH: !!process.env.DB_PATH,
    SESSIONS_DIR: !!process.env.SESSIONS_DIR,
    SESSION_SECRET: !!process.env.SESSION_SECRET,
    RESET_TOKEN: !!process.env.RESET_TOKEN,
    PORT: process.env.PORT || '(default 3000)'
  };
  let users = [];
  try { users = await dbAll(`SELECT id,email,role FROM users ORDER BY id`); } catch {}
  res.type('html').send(`
    <h1>TradeX Diagnostics</h1>
    <h3>Environment vars (true=present)</h3>
    <pre>${JSON.stringify(env, null, 2)}</pre>
    <h3>Users</h3>
    <pre>${users.length ? JSON.stringify(users, null, 2) : '(none or DB error)'}</pre>
    <h3>Routes</h3>
    <ul>
      <li><a href="/login">/login</a></li>
      <li><a href="/about">/about</a></li>
      <li>/reset-password ${process.env.RESET_TOKEN ? '(enabled)' : '(disabled)'}</li>
      <li>/bootstrap-admin ${process.env.RESET_TOKEN ? '(enabled)' : '(disabled)'}</li>
      <li>/debug-users ${process.env.RESET_TOKEN ? '(enabled)' : '(disabled)'}</li>
    </ul>
  `);
});

// ---- Boot ----
ensureSchema().then(() => {
  app.listen(PORT, () => console.log(`${APP_NAME} running at http://localhost:${PORT}`));
}).catch(e => { console.error('Migration error', e); process.exit(1); });
