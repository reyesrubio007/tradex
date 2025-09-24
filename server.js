
// TradeX v0.7 — Multi-user + Roles + Password Reset + SQLite Sessions
// Dependencies: express sqlite3 multer csv-parse express-session bcryptjs connect-sqlite3
// Env vars (Render):
//   DB_PATH=/var/data/journal.db
//   SESSION_SECRET=<long_random_string>
//   NODE_VERSION=20
//   RESET_TOKEN=<temporary for password reset>
//   SESSIONS_DIR=/var/data

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const multer = require('multer');
const { parse } = require('csv-parse');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;
const APP_NAME = 'TradeX';

// --- favicon ---
const FAVICON_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="12" fill="#0f172a"/>
  <path d="M16 40 L28 26 L36 34 L48 20" stroke="#10b981" stroke-width="6" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="48" cy="20" r="3" fill="#10b981"/>
</svg>`;
app.get('/favicon.ico', (req,res)=>res.type('image/svg+xml').send(FAVICON_SVG));

app.use(express.urlencoded({ extended:true }));
app.use(express.json());

// --- sessions ---
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_only_change_me';
const DB_PATH = process.env.DB_PATH || path.join(__dirname,'journal.db');
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
    maxAge: 1000*60*60*24*7
  }
}));

// --- db helpers ---
const db = new sqlite3.Database(DB_PATH);
const dbAll=(sql,p=[])=>new Promise((res,rej)=>db.all(sql,p,(e,r)=>e?rej(e):res(r)));
const dbGet=(sql,p=[])=>new Promise((res,rej)=>db.get(sql,p,(e,r)=>e?rej(e):res(r)));
const dbRun=(sql,p=[])=>new Promise((res,rej)=>db.run(sql,p,function(e){e?rej(e):res({changes:this.changes,lastID:this.lastID});}));

async function ensureSchema(){
  await dbRun(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE,password_hash TEXT,role TEXT,created_at TEXT DEFAULT (datetime('now')))`);
  await dbRun(`CREATE TABLE IF NOT EXISTS trades (id INTEGER PRIMARY KEY AUTOINCREMENT,trade_date TEXT,symbol TEXT,side TEXT,qty INTEGER,entry_price REAL,exit_price REAL,fees REAL DEFAULT 0,notes TEXT)`);
  const cols = await dbAll(`PRAGMA table_info(trades)`);
  if(!cols.find(c=>c.name==='user_id')){
    await dbRun(`ALTER TABLE trades ADD COLUMN user_id INTEGER`);
    const first=await dbGet(`SELECT id FROM users ORDER BY id ASC LIMIT 1`);
    if(first) await dbRun(`UPDATE trades SET user_id=? WHERE user_id IS NULL`,[first.id]);
  }
}

function requireAuth(req,res,next){ if(req.session&&req.session.user) return next(); return res.redirect('/login'); }
function requireAdmin(req,res,next){ if(req.session?.user?.role==='admin') return next(); return res.status(403).send('Admins only'); }

// --- auth ---
app.get('/login', async (req,res)=>{
  const count=await dbGet(`SELECT COUNT(*) as c FROM users`);
  const canSignup=(count&&count.c===0);
  res.send(`<h1>${APP_NAME} Login</h1>
    <form method="POST">
      <input name=email placeholder="email">
      <input name=password type=password placeholder="password">
      <button>Login</button>
    </form>
    ${canSignup?'<a href="/signup">Create first admin</a>':''}`);
});

app.post('/login', async (req,res)=>{
  const email=String(req.body.email||'').toLowerCase();
  const pass=String(req.body.password||'');
  const u=await dbGet(`SELECT * FROM users WHERE email=?`,[email]);
  if(!u) return res.send('Invalid');
  const ok=await bcrypt.compare(pass,u.password_hash);
  if(!ok) return res.send('Invalid');
  req.session.user={id:u.id,email:u.email,role:u.role};
  res.redirect('/');
});

app.get('/signup', async (req,res)=>{
  const c=await dbGet(`SELECT COUNT(*) as c FROM users`);
  if(c.c!==0) return res.redirect('/login');
  res.send(`<h1>${APP_NAME} First Admin</h1>
    <form method="POST">
      <input name=email placeholder="email">
      <input name=password type=password placeholder="password">
      <button>Create</button>
    </form>`);
});

app.post('/signup', async (req,res)=>{
  const email=String(req.body.email||'').toLowerCase();
  const pass=String(req.body.password||'');
  if(pass.length<6) return res.send('Too short');
  const hash=await bcrypt.hash(pass,10);
  await dbRun(`INSERT INTO users(email,password_hash,role) VALUES(?,?,?)`,[email,hash,'admin']);
  res.redirect('/login');
});

app.post('/logout',(req,res)=>req.session.destroy(()=>res.redirect('/login')));

// --- password reset ---
app.get('/reset-password',(req,res)=>{
  if(!process.env.RESET_TOKEN) return res.status(404).send('Not enabled');
  res.send(`<h1>Password Reset</h1>
    <form method="POST">
      <input name=email placeholder="email">
      <input name=password type=password placeholder="new password">
      <input name=token placeholder="RESET_TOKEN">
      <button>Reset</button>
    </form>`);
});

app.post('/reset-password', async (req,res)=>{
  const token=String(req.body.token||'');
  if(!process.env.RESET_TOKEN||token!==process.env.RESET_TOKEN) return res.status(403).send('Bad token');
  const email=String(req.body.email||'').toLowerCase();
  const pass=String(req.body.password||'');
  if(pass.length<6) return res.send('Too short');
  const hash=await bcrypt.hash(pass,10);
  const r=await dbRun(`UPDATE users SET password_hash=? WHERE email=?`,[hash,email]);
  if(!r.changes) return res.send('User not found');
  res.send('Password updated. <a href="/login">Login</a>');
});

// --- admin users ---
app.get('/admin/users',requireAuth,requireAdmin,async(req,res)=>{
  const users=await dbAll(`SELECT id,email,role FROM users`);
  res.send(`<h1>Users</h1>
    ${users.map(u=>`<div>${u.email} (${u.role})</div>`).join('')}
    <form method=POST>
      <input name=email placeholder="email">
      <input name=password type=password placeholder="password">
      <select name=role><option>user</option><option>admin</option></select>
      <button>Add</button>
    </form>`);
});

app.post('/admin/users',requireAuth,requireAdmin,async(req,res)=>{
  const email=String(req.body.email||'').toLowerCase();
  const pass=String(req.body.password||'');
  const role=(req.body.role==='admin')?'admin':'user';
  const hash=await bcrypt.hash(pass,10);
  await dbRun(`INSERT INTO users(email,password_hash,role) VALUES(?,?,?)`,[email,hash,role]);
  res.redirect('/admin/users');
});

// --- dashboard ---
app.get('/',requireAuth,(req,res)=>{
  res.send(`<h1>${APP_NAME}</h1>
    <p>Hello ${req.session.user.email} (${req.session.user.role})</p>
    <form method=POST action=/logout><button>Logout</button></form>`);
});

// --- about ---
app.get('/about',(_req,res)=>res.send(`<h1>${APP_NAME} About</h1>`));

// --- start ---
ensureSchema().then(()=>app.listen(PORT,()=>console.log(`${APP_NAME} at http://localhost:${PORT}`)));
