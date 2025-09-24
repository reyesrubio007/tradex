// TradeX v0.5 — Multi-user + Roles (Admin/User) + Per-user data isolation
// Dependencies: express sqlite3 multer csv-parse express-session bcryptjs
// Env vars (Render): DB_PATH=/var/data/journal.db , SESSION_SECRET=long_random_string , NODE_VERSION=20

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const { parse } = require('csv-parse');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;
const APP_NAME = 'TradeX';

// ---- Favicon ----
const FAVICON_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="12" fill="#0f172a"/>
  <path d="M16 40 L28 26 L36 34 L48 20" stroke="#10b981" stroke-width="6" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="48" cy="20" r="3" fill="#10b981"/>
</svg>`;
app.get('/favicon.ico', (req, res) => res.type('image/svg+xml').send(FAVICON_SVG));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ---- Sessions ----
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_only_change_me_please_1234567890';
app.use(session({
  name: 'tradex.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: !!process.env.RENDER, maxAge: 1000*60*60*24*7 }
}));

// ---- DB ----
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'journal.db');
const db = new sqlite3.Database(DB_PATH);

const dbAll = (sql,p=[])=>new Promise((res,rej)=>db.all(sql,p,(e,r)=>e?rej(e):res(r)));
const dbGet = (sql,p=[])=>new Promise((res,rej)=>db.get(sql,p,(e,r)=>e?rej(e):res(r)));
const dbRun = (sql,p=[])=>new Promise((res,rej)=>db.run(sql,p,function(e){e?rej(e):res({changes:this.changes,lastID:this.lastID});}));

// Schema + migrations
async function ensureSchema(){
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
  // Add user_id column if missing
  const cols = await dbAll(`PRAGMA table_info(trades)`);
  if (!cols.find(c=>c.name==='user_id')){
    await dbRun(`ALTER TABLE trades ADD COLUMN user_id INTEGER`);
    const firstUser = await dbGet(`SELECT id FROM users ORDER BY id ASC LIMIT 1`);
    if (firstUser){ await dbRun(`UPDATE trades SET user_id = ? WHERE user_id IS NULL`, [firstUser.id]); }
  }
}

function isValidDateYYYYMMDD(s){ return /^\\d{4}-\\d{2}-\\d{2}$/.test(s); }
function toNum(x,d=0){ const n=parseFloat(x); return Number.isFinite(n)?n:d; }
function computePnl(r){ const g = r.side==='LONG'?(r.exit_price-r.entry_price)*r.qty:(r.entry_price-r.exit_price)*r.qty; return g - (r.fees||0); }
function currency(n){ const v=Number(n||0); const s=v.toFixed(2); return v>=0?('$'+s):('-$'+Math.abs(v).toFixed(2)); }
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\\"/g,'&quot;').replace(/'/g,'&#039;'); }

function requireAuth(req,res,next){ if(req.session&&req.session.user) return next(); return res.redirect('/login'); }
function requireAdmin(req,res,next){ if(req.session&&req.session.user&&req.session.user.role==='admin') return next(); return res.status(403).send('Admins only'); }

// --- Auth ---
app.get('/login', async (req,res)=>{
  const count = await dbGet(`SELECT COUNT(*) AS c FROM users`);
  const canSignup = (count&&count.c===0);
  const err = req.query.err?`<div class='mb-2 text-rose-600 text-sm'>${esc(req.query.err)}</div>`:'';
  res.send(`<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>${APP_NAME} • Login</title><link rel='icon' href='/favicon.ico'><script src='https://cdn.tailwindcss.com'></script></head><body class='bg-slate-50 text-slate-900'><div class='max-w-md mx-auto p-6 mt-10 bg-white rounded-2xl shadow'><h1 class='text-2xl font-bold mb-4 text-center'>${APP_NAME} — Login</h1>${err}<form method='POST' action='/login' class='space-y-3'><div><label class='block text-xs text-slate-600'>Email</label><input name='email' type='email' required class='w-full border rounded-xl p-2'></div><div><label class='block text-xs text-slate-600'>Password</label><input name='password' type='password' required class='w-full border rounded-xl p-2'></div><button class='w-full px-4 py-2 rounded-xl shadow bg-slate-900 text-white'>Sign in</button></form>${canSignup?"<p class='text-xs text-slate-500 mt-3 text-center'>First time here? <a class='underline' href='/signup'>Create the first admin</a></p>":""}</div></body></html>`);
});

app.post('/login', async (req,res)=>{
  try{
    const email=String(req.body.email||'').trim().toLowerCase();
    const pass=String(req.body.password||'');
    const u=await dbGet(`SELECT * FROM users WHERE email=?`,[email]);
    if(!u) return res.redirect('/login?err='+encodeURIComponent('Invalid email or password'));
    const ok=await bcrypt.compare(pass,u.password_hash);
    if(!ok) return res.redirect('/login?err='+encodeURIComponent('Invalid email or password'));
    req.session.user={id:u.id,email:u.email,role:u.role};
    res.redirect('/');
  }catch(e){ console.error(e); res.redirect('/login?err='+encodeURIComponent('Login error')); }
});

app.get('/signup', async (req,res)=>{
  const count = await dbGet(`SELECT COUNT(*) AS c FROM users`);
  if (!count || count.c!==0) return res.redirect('/login');
  res.send(`<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>${APP_NAME} • Create Admin</title><link rel='icon' href='/favicon.ico'><script src='https://cdn.tailwindcss.com'></script></head><body class='bg-slate-50 text-slate-900'><div class='max-w-md mx-auto p-6 mt-10 bg-white rounded-2xl shadow'><h1 class='text-2xl font-bold mb-4 text-center'>${APP_NAME} — First Admin</h1><form method='POST' action='/signup' class='space-y-3'><div><label class='block text-xs text-slate-600'>Email</label><input name='email' type='email' required class='w-full border rounded-xl p-2'></div><div><label class='block text-xs text-slate-600'>Password</label><input name='password' type='password' minlength='6' required class='w-full border rounded-xl p-2'></div><button class='w-full px-4 py-2 rounded-xl shadow bg-slate-900 text-white'>Create Admin</button></form></div></body></html>`);
});

app.post('/signup', async (req,res)=>{
  try{
    const count = await dbGet(`SELECT COUNT(*) AS c FROM users`);
    if (!count || count.c!==0) return res.redirect('/login');
    const email=String(req.body.email||'').trim().toLowerCase();
    const pass=String(req.body.password||'');
    if(!email||pass.length<6) return res.redirect('/signup?err='+encodeURIComponent('Invalid email or short password'));
    const hash=await bcrypt.hash(pass,10);
    await dbRun(`INSERT INTO users(email,password_hash,role) VALUES(?,?, 'admin')`,[email,hash]);
    res.redirect('/login');
  }catch(e){ console.error(e); res.redirect('/signup?err='+encodeURIComponent('Signup error')); }
});

app.post('/logout',(req,res)=>{ req.session.destroy(()=>res.redirect('/login')); });

// --- Admin: manage users ---
app.get('/admin/users', requireAuth, requireAdmin, async (req,res)=>{
  const users = await dbAll(`SELECT id,email,role,created_at FROM users ORDER BY id ASC`);
  res.send(`<h1>Users</h1>
    <form method="POST" action="/admin/users">
      <input name="email" type="email" placeholder="email@example.com" required>
      <input name="password" type="password" minlength="6" required>
      <select name="role"><option value="user">user</option><option value="admin">admin</option></select>
      <button>Add user</button>
    </form>
    <ul>${users.map(u=>`<li>${esc(u.email)} (${u.role})</li>`).join('')}</ul>`);
});

app.post('/admin/users', requireAuth, requireAdmin, async (req,res)=>{
  try{
    const email=String(req.body.email||'').trim().toLowerCase();
    const pass=String(req.body.password||'');
    const role = (req.body.role==='admin')?'admin':'user';
    if(!email||pass.length<6) return res.redirect('/admin/users?err=bad');
    const hash=await bcrypt.hash(pass,10);
    await dbRun(`INSERT INTO users(email,password_hash,role) VALUES(?,?,?)`,[email,hash,role]);
    res.redirect('/admin/users');
  }catch(e){ console.error(e); res.redirect('/admin/users?err=fail'); }
});

// --- Example Dashboard ---
app.get('/', requireAuth, async (req,res)=>{
  res.send(`<h1>Welcome ${esc(req.session.user.email)}</h1>
    <p>Role: ${req.session.user.role}</p>
    <p><a href="/admin/users">Manage users (admin only)</a></p>
    <form method="POST" action="/logout"><button>Logout</button></form>`);
});

// --- About (public) ---
app.get('/about', (_req,res)=>{ res.send(`<h1>${APP_NAME} • About</h1><p>Multi-user trading journal</p>`); });

// Boot
ensureSchema().then(()=>{ app.listen(PORT,()=>console.log(`${APP_NAME} running at http://localhost:${PORT}`)); }).catch(e=>{ console.error('Migration error',e); process.exit(1); });
