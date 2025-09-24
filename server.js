
// TradeX v0.9.2 — full app with session fix + full dashboard
// ENV (Render):
//  DB_PATH=/var/data/journal.db
//  SESSIONS_DIR=/var/data
//  SESSION_SECRET=<long_random>
//  NODE_VERSION=20
//  RESET_TOKEN=<temporary when needed, then remove>

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

// ✅ Important for Render secure cookies behind proxy
app.set('trust proxy', 1);

// ---- Middleware ----
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
    notes TEXT,
    user_id INTEGER
  )`);
}

// ---- Sessions ----
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_secret_change_me';
const sessionsDir = process.env.SESSIONS_DIR || path.dirname(DB_PATH);

app.use(session({
  name: 'tradex.sid',
  secret: SESSION_SECRET,
  store: new SQLiteStore({
    dir: sessionsDir,
    db: 'sessions.db'
  }),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: !!process.env.RENDER, // secure on Render
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

// ---- Helpers ----
const esc = s => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\\"/g, '&quot;').replace(/'/g, '&#039;');
const isValidDate = s => /^\d{4}-\d{2}-\d{2}$/.test(s);
const toNum = (x, d = 0) => { const n = parseFloat(x); return Number.isFinite(n) ? n : d; };
const computePnl = r => {
  const g = r.side === 'LONG' ? (r.exit_price - r.entry_price) * r.qty
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

// ---- Guards ----
function requireAuth(req, res, next) { if (req.session && req.session.user) return next(); return res.redirect('/login'); }
function requireAdmin(req, res, next) { if (req.session?.user?.role === 'admin') return next(); return res.status(403).send('Admins only'); }

// ---- Login/Signup ----
app.get('/login', async (req, res) => {
  const c = await dbGet(`SELECT COUNT(*) AS c FROM users`);
  const canSignup = (c && c.c === 0);
  const err = req.query.err ? `<div style="color:#b91c1c">${esc(req.query.err)}</div>` : '';
  res.send(`<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>${APP_NAME} • Login</title></head><body><h1>${APP_NAME} — Login</h1>${err}<form method='POST'><input name='email' placeholder='email'><input type='password' name='password' placeholder='password'><button>Login</button></form>${canSignup ? "<p><a href='/signup'>Create the first admin</a></p>" : ""}</body></html>`);
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
    req.session.save(err => {
      if (err) return res.redirect('/login?err=' + encodeURIComponent('Session error'));
      res.redirect('/');
    });
  } catch (e) {
    res.redirect('/login?err=' + encodeURIComponent('Login error'));
  }
});

app.get('/signup', async (req, res) => {
  const c = await dbGet(`SELECT COUNT(*) AS c FROM users`);
  if (!c || c.c !== 0) return res.redirect('/login');
  res.send(`<!doctype html><html><body><h1>Create Admin</h1><form method="POST"><input name="email"><input name="password" type="password" minlength="6"><button>Create</button></form></body></html>`);
});

app.post('/signup', async (req, res) => {
  try {
    const c = await dbGet(`SELECT COUNT(*) AS c FROM users`);
    if (!c || c.c !== 0) return res.redirect('/login');
    const email = String(req.body.email || '').trim().toLowerCase();
    const pass = String(req.body.password || '');
    if (!email || pass.length < 6) return res.redirect('/signup?err=bad input');
    const hash = await bcrypt.hash(pass, 10);
    await dbRun(`INSERT INTO users(email,password_hash,role) VALUES(?,?, 'admin')`, [email, hash]);
    res.redirect('/login');
  } catch (e) { res.redirect('/signup?err=error'); }
});

app.post('/logout', (req, res) => { req.session.destroy(() => res.redirect('/login')); });

// ---- Admin users ----
app.get('/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const users = await dbAll(`SELECT id,email,role,created_at FROM users ORDER BY id ASC`);
  res.send(`<!doctype html><html><body><h1>Users</h1><a href="/">Back</a><ul>${users.map(u => `<li>${esc(u.email)} (${u.role}) ${u.id === req.session.user.id ? '' : `<form method="POST" action="/admin/users/${u.id}/delete" style="display:inline"><button>Delete</button></form>`}</li>`).join('')}</ul><h2>Add user</h2><form method="POST" action="/admin/users"><input name="email" type="email"><input name="password" type="password" minlength="6"><select name="role"><option value="user">user</option><option value="admin">admin</option></select><button>Add</button></form></body></html>`);
});

app.post('/admin/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const pass = String(req.body.password || '');
    const role = req.body.role === 'admin' ? 'admin' : 'user';
    if (!email || pass.length < 6) return res.redirect('/admin/users');
    const hash = await bcrypt.hash(pass, 10);
    await dbRun(`INSERT INTO users(email,password_hash,role) VALUES(?,?,?)`, [email, hash, role]);
    res.redirect('/admin/users');
  } catch (e) { res.redirect('/admin/users'); }
});

app.post('/admin/users/:id/delete', requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (id === req.session.user.id) return res.redirect('/admin/users');
    const admins = await dbGet(`SELECT COUNT(*) AS c FROM users WHERE role='admin'`);
    const victim = await dbGet(`SELECT role FROM users WHERE id=?`, [id]);
    if (victim && victim.role === 'admin' && admins && admins.c <= 1) return res.redirect('/admin/users');
    await dbRun(`DELETE FROM users WHERE id=?`, [id]);
    res.redirect('/admin/users');
  } catch (e) { res.redirect('/admin/users'); }
});

// ---- CSV Upload ----
const upload = multer({ dest: path.join(__dirname, 'uploads') });
const normalizeDate = s => {
  if (!s) return null;
  s = String(s).trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  const m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{2,4})$/);
  if (m) { let mm = +m[1], dd = +m[2], yy = +m[3]; if (yy < 100) yy += 2000;
    return `${yy}-${String(mm).padStart(2, '0')}-${String(dd).padStart(2, '0')}`; }
  return null;
};
const normalizeSide = s => { s = String(s || '').trim().toUpperCase(); return s.startsWith('S') ? 'SHORT' : 'LONG'; };

app.post('/import', requireAuth, upload.single('csvfile'), async (req, res) => {
  if (!req.file) return res.status(400).send('No file');
  const uid = req.session.user.id; const filePath = req.file.path; const rows = [];
  try {
    await new Promise((resolve, reject) => {
      fs.createReadStream(filePath)
        .pipe(parse({ columns: true, skip_empty_lines: true, trim: true }))
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
  } catch (e) { res.status(500).send('Import error: ' + e.message); }
  finally { fs.unlink(filePath, () => {}); }
});

// ---- Dashboard ----
function buildCalendar(dailyEntries, year, monthIdx) {
  const map = new Map(dailyEntries.map(d => [d.date, d.total]));
  const first = new Date(Date.UTC(year, monthIdx, 1));
  const last = new Date(Date.UTC(year, monthIdx + 1, 0));
  const dim = last.getUTCDate();
  const fdow = first.getUTCDay();
  const cells = [];
  for (let i=0;i<fdow;i++) cells.push(null);
  for (let day=1; day<=dim; day++) {
    const ds = `${year}-${String(monthIdx+1).padStart(2,'0')}-${String(day).padStart(2,'0')}`;
    const pnl = map.get(ds) || 0;
    cells.push({ ds, pnl });
  }
  while (cells.length % 7 !== 0) cells.push(null);
  const weeks = [];
  for (let i=0;i<cells.length;i+=7) weeks.push(cells.slice(i,i+7));
  const weekdayHeader = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].map(d=>`<div class='text-center'>${d}</div>`).join('');
  const grid = weeks.map(week => week.map(c=>{
    if(!c) return "<div class='h-20 rounded bg-slate-100'></div>";
    const pnl = +c.pnl;
    const cls = pnl>0?'bg-emerald-200':pnl<0?'bg-rose-200':'bg-slate-100';
    const tone = pnl>0?'text-emerald-700':pnl<0?'text-rose-700':'text-slate-500';
    const txt = pnl?((pnl>=0?'+':'')+pnl.toFixed(2)):'';
    return `<div class='h-20 rounded ${cls} p-2 flex flex-col justify-between'><div class='text-[10px] text-slate-600'>${c.ds}</div><div class='text-right text-sm font-mono ${tone}'>${txt}</div></div>`;
  }).join('')).join('');
  return `<div class='grid grid-cols-7 text-xs text-slate-500 mb-2'>${weekdayHeader}</div><div class='grid grid-cols-7 gap-2'>${grid}</div>`;
}

app.get('/', requireAuth, async (req, res) => {
  try {
    const uid = req.session.user.id;
    const now = new Date();
    const year = parseInt(req.query.y || now.getUTCFullYear());
    const monthIdx = parseInt(req.query.m || (now.getUTCMonth()+1)) - 1;

    const trades = await dbAll(`SELECT id,trade_date,symbol,side,qty,entry_price,exit_price,fees,notes FROM trades WHERE user_id=? ORDER BY trade_date DESC,id DESC`, [uid]);
    const withPnL = trades.map(t => ({ ...t, pnl: computePnl(t) }));

    const dailyMap = new Map();
    for (const t of withPnL) dailyMap.set(t.trade_date, (dailyMap.get(t.trade_date)||0) + t.pnl);
    const dailySorted = Array.from(dailyMap.entries()).sort((a,b)=>a[0].localeCompare(b[0])).map(([date,total])=>({date,total}));

    const totalTrades = withPnL.length;
    const winners = withPnL.filter(t=>t.pnl>0);
    const losers = withPnL.filter(t=>t.pnl<0);
    const grossPnL = withPnL.reduce((a,b)=>a+b.pnl,0);
    const winRate = totalTrades ? (winners.length/totalTrades)*100 : 0;

    const monthStr = `${year}-${String(monthIdx+1).padStart(2,'0')}`;
    const mtd = dailySorted.filter(d=>d.date.startsWith(monthStr)).reduce((a,b)=>a+b.total,0);

    const prev = new Date(Date.UTC(year, monthIdx-1, 1));
    const next = new Date(Date.UTC(year, monthIdx+1, 1));
    const calHTML = buildCalendar(dailySorted, year, monthIdx);

    res.send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${APP_NAME} • Dashboard</title><script src="https://cdn.tailwindcss.com"></script></head><body class="bg-slate-50 text-slate-900"><div class="max-w-6xl mx-auto p-6 space-y-6"><header class="flex items-center justify-between"><h1 class="text-2xl font-bold">${APP_NAME}</h1><nav class="flex items-center gap-3 text-sm">${req.session.user.role==='admin'?'<a class="underline" href="/admin/users">Users</a>':''}<form method="POST" action="/logout"><button class="underline text-rose-700">Logout (${esc(req.session.user.email)})</button></form></nav></header><section class="grid md:grid-cols-4 gap-4"><div class="bg-white rounded-2xl shadow p-5"><div class="text-xs text-slate-500">Total Trades</div><div class="text-2xl font-semibold mt-1">${totalTrades}</div></div><div class="bg-white rounded-2xl shadow p-5"><div class="text-xs text-slate-500">Win Rate</div><div class="text-2xl font-semibold mt-1">${winRate.toFixed(1)}%</div></div><div class="bg-white rounded-2xl shadow p-5"><div class="text-xs text-slate-500">Gross PnL</div><div class="text-2xl font-semibold mt-1 ${grossPnL>=0?'text-emerald-600':'text-rose-600'}">${currency(grossPnL)}</div></div><div class="bg-white rounded-2xl shadow p-5"><div class="text-xs text-slate-500">MTD PnL</div><div class="text-2xl font-semibold mt-1 ${mtd>=0?'text-emerald-600':'text-rose-600'}">${currency(mtd)}</div></div></section><section class="bg-white rounded-2xl shadow p-5"><div class="flex items-center justify-between mb-3"><h2 class="text-xl font-semibold">Calendar PnL — ${year}-${String(monthIdx+1).padStart(2,'0')}</h2><div class="flex gap-2"><a class="px-3 py-1 border rounded" href="/?y=${prev.getUTCFullYear()}&m=${prev.getUTCMonth()+1}">◀ Prev</a><a class="px-3 py-1 border rounded" href="/?y=${next.getUTCFullYear()}&m=${next.getUTCMonth()+1}">Next ▶</a></div></div>${calHTML}</section><section class="bg-white rounded-2xl shadow p-5"><h2 class="text-xl font-semibold mb-3">Add Trade</h2><form method="POST" action="/trades" class="grid grid-cols-2 gap-3"><div class="col-span-2"><label class="block text-xs text-slate-600">Date</label><input name="trade_date" type="date" required class="w-full border rounded p-2"></div><div><label class="block text-xs text-slate-600">Symbol</label><input name="symbol" required class="w-full border rounded p-2"></div><div><label class="block text-xs text-slate-600">Side</label><select name="side" class="w-full border rounded p-2"><option>LONG</option><option>SHORT</option></select></div><div><label class="block text-xs text-slate-600">Qty</label><input name="qty" type="number" min="1" value="1" required class="w-full border rounded p-2"></div><div><label class="block text-xs text-slate-600">Entry</label><input name="entry_price" type="number" step="0.01" required class="w-full border rounded p-2"></div><div><label class="block text-xs text-slate-600">Exit</label><input name="exit_price" type="number" step="0.01" required class="w-full border rounded p-2"></div><div class="col-span-2"><label class="block text-xs text-slate-600">Fees</label><input name="fees" type="number" step="0.01" value="0" class="w-full border rounded p-2"></div><div class="col-span-2"><label class="block text-xs text-slate-600">Notes</label><textarea name="notes" rows="2" class="w-full border rounded p-2"></textarea></div><div class="col-span-2"><button class="px-4 py-2 rounded shadow bg-slate-900 text-white">Save</button></div></form></section><section class="bg-white rounded-2xl shadow p-5"><h2 class="text-xl font-semibold mb-3">Trades</h2><div class="overflow-x-auto"><table class="min-w-full text-sm"><thead><tr class="text-left border-b"><th class="py-2 pr-4">Date</th><th class="py-2 pr-4">Symbol</th><th class="py-2 pr-4">Side</th><th class="py-2 pr-4">Qty</th><th class="py-2 pr-4">Entry</th><th class="py-2 pr-4">Exit</th><th class="py-2 pr-4">Fees</th><th class="py-2 pr-4">PnL</th><th class="py-2 pr-4">Notes</th><th class="py-2">Actions</th></tr></thead><tbody>${withPnL.length ? withPnL.map(t => `<tr class="border-b last:border-b-0 align-top"><td class="py-2 pr-4">${t.trade_date}</td><td class="py-2 pr-4 font-mono">${t.symbol}</td><td class="py-2 pr-4">${t.side}</td><td class="py-2 pr-4">${t.qty}</td><td class="py-2 pr-4">${Number(t.entry_price).toFixed(2)}</td><td class="py-2 pr-4">${Number(t.exit_price).toFixed(2)}</td><td class="py-2 pr-4">${Number(t.fees||0).toFixed(2)}</td><td class="py-2 pr-4 font-mono ${t.pnl>=0?'text-emerald-600':'text-rose-600'}">${t.pnl.toFixed(2)}</td><td class="py-2 pr-4 whitespace-pre-wrap">${t.notes?esc(t.notes):''}</td><td class="py-2"><form method="POST" action="/trades/${t.id}/delete" onsubmit="return confirm('Delete?')"><button class="underline text-rose-700">Delete</button></form></td></tr>`).join('') : `<tr><td class="py-2" colspan="10">No trades yet.</td></tr>`}</tbody></table></div></section><footer class="text-xs text-slate-500 text-center py-6">${APP_NAME} • v0.9.2</footer></div></body></html>`);
  } catch (err) {
    res.status(500).send('Server error');
  }
});

app.post('/trades', requireAuth, async (req, res) => {
  try {
    const uid = req.session.user.id;
    const { trade_date, symbol, side, qty, entry_price, exit_price, fees = 0, notes = '' } = req.body;
    if (!isValidDate(trade_date)) throw new Error('Invalid date');
    if (!symbol || (side !== 'LONG' && side !== 'SHORT')) throw new Error('Invalid symbol/side');
    const qtyNum = parseInt(qty, 10);
    const entry = toNum(entry_price);
    const exit = toNum(exit_price);
    const fee = toNum(fees, 0);
    if (!(qtyNum > 0) || !Number.isFinite(entry) || !Number.isFinite(exit)) throw new Error('Invalid numbers');
    await dbRun(`INSERT INTO trades (trade_date,symbol,side,qty,entry_price,exit_price,fees,notes,user_id) VALUES (?,?,?,?,?,?,?,?,?)`,
      [trade_date, symbol.trim().toUpperCase(), side, qtyNum, entry, exit, fee, notes, uid]);
    res.redirect('/');
  } catch (e) { res.status(400).send('Bad request: ' + e.message); }
});

app.post('/trades/:id/delete', requireAuth, async (req, res) => {
  try {
    const uid = req.session.user.id;
    const id = parseInt(req.params.id, 10);
    await dbRun(`DELETE FROM trades WHERE id=? AND user_id=?`, [id, uid]);
    res.redirect('/');
  } catch (e) { res.status(400).send('Bad request'); }
});

// ---- Reset password (token-guarded) ----
app.get('/reset-password', (req, res) => {
  if (!process.env.RESET_TOKEN) return res.status(404).send('Not enabled');
  res.send(`<h1>Password Reset</h1><form method="POST"><input name="email"><input name="password" type="password" minlength="6"><input name="token"><button>Reset</button></form>`);
});
app.post('/reset-password', async (req, res) => {
  try {
    const token = String(req.body.token || '');
    if (!process.env.RESET_TOKEN || token !== process.env.RESET_TOKEN) return res.status(403).send('Bad token');
    const email = String(req.body.email || '').trim().toLowerCase();
    const pass = String(req.body.password || '');
    if (!email || pass.length < 6) return res.status(400).send('Invalid input');
    const hash = await bcrypt.hash(pass, 10);
    const r = await dbRun(`UPDATE users SET password_hash=? WHERE email=?`, [hash, email]);
    if (!r.changes) return res.status(404).send('User not found');
    res.send('Password updated. <a href="/login">Go to login</a>');
  } catch (e) { res.status(500).send('Reset error'); }
});

// ---- Bootstrap admin (token-guarded, debuggable) ----
app.get('/bootstrap-admin', (req, res) => {
  if (!process.env.RESET_TOKEN) return res.status(404).send('Not enabled');
  res.send(`<h1>Create Admin</h1><form method="POST"><input name="email"><input name="password" type="password" minlength="6"><input name="token"><button>Create</button></form>`);
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
    await dbRun(`INSERT INTO users(email,password_hash,role) VALUES(?,?, 'admin')`, [email, hash]);
    res.send('Admin created. <a href="/login">Log in</a>');
  } catch (e) { res.status(500).send('Bootstrap error: ' + e.message); }
});

// ---- Diagnostics ----
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
  res.type('html').send(`<pre>${JSON.stringify({ env, users }, null, 2)}</pre>`);
});

// ---- Boot ----
ensureSchema().then(() => {
  app.listen(PORT, () => console.log(`${APP_NAME} running at http://localhost:${PORT}`));
}).catch(e => { console.error('Migration error', e); process.exit(1); });
