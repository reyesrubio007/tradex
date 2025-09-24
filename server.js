// TradeX v0.9.1 — full app with session fix
//  • Multi-user (admin/user)
//  • SQLite session store (connect-sqlite3)
//  • Calendar PnL, CSV import, summaries
//  • Admin panel, password reset, bootstrap-admin
//  • Diagnostics page /_diag
//  • FIXED: trust proxy + save session on login

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

// ✅ Important for Render secure cookies
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
const esc = s => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const computePnl = r => {
  const g = r.side === 'LONG'
    ? (r.exit_price - r.entry_price) * r.qty
    : (r.entry_price - r.exit_price) * r.qty;
  return g - (r.fees || 0);
};

// ---- Auth guards ----
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect('/login');
}
function requireAdmin(req, res, next) {
  if (req.session && req.session.user && req.session.user.role === 'admin') return next();
  return res.status(403).send('Admins only');
}

// ---- Routes ----
app.get('/login', async (req, res) => {
  const err = req.query.err ? `<div style="color:#b91c1c">${esc(req.query.err)}</div>` : '';
  res.send(`<h1>Login</h1>${err}<form method="POST"><input name="email"><input name="password" type="password"><button>Login</button></form>`);
});

// ✅ FIXED: save session before redirect
app.post('/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const pass = String(req.body.password || '');
    const u = await dbGet(`SELECT * FROM users WHERE email=?`, [email]);
    if (!u) return res.redirect('/login?err=Invalid');
    const ok = await bcrypt.compare(pass, u.password_hash);
    if (!ok) return res.redirect('/login?err=Invalid');

    req.session.user = { id: u.id, email: u.email, role: u.role };
    req.session.save(err => {
      if (err) {
        console.error('Session save error:', err);
        return res.redirect('/login?err=Session');
      }
      res.redirect('/');
    });
  } catch (e) {
    console.error(e);
    res.redirect('/login?err=Error');
  }
});

app.post('/logout', (req, res) => { req.session.destroy(() => res.redirect('/login')); });

app.get('/', requireAuth, async (req, res) => {
  const trades = await dbAll(`SELECT * FROM trades WHERE user_id=? ORDER BY trade_date DESC`, [req.session.user.id]);
  const withPnL = trades.map(t => ({ ...t, pnl: computePnl(t) }));
  res.send(`<h1>Dashboard</h1><p>Welcome ${esc(req.session.user.email)}</p><pre>${JSON.stringify(withPnL, null, 2)}</pre><form method="POST" action="/logout"><button>Logout</button></form>`);
});

// ---- Bootstrap admin ----
app.get('/bootstrap-admin', (req, res) => {
  if (!process.env.RESET_TOKEN) return res.status(404).send('Not enabled');
