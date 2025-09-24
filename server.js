
// TraderX v0.3
// + CSV import (upload broker CSVs)
// + Weekly & Monthly PnL summaries
// + Cloud‑ready notes (Render/Railway) – SQLite stays local unless you add a volume
//
// Run locally:
//   npm init -y
//   npm i express sqlite3 multer csv-parse
//   node server.js  → http://localhost:3000

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const { parse } = require('csv-parse');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// --- SQLite ---
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'journal.db');
const db = new sqlite3.Database(DB_PATH);

db.serialize(() => {
  db.run(`
  CREATE TABLE IF NOT EXISTS trades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trade_date TEXT NOT NULL,              -- YYYY-MM-DD
    symbol TEXT NOT NULL,
    side TEXT NOT NULL CHECK(side IN ('LONG','SHORT')),
    qty INTEGER NOT NULL,
    entry_price REAL NOT NULL,
    exit_price REAL NOT NULL,
    fees REAL NOT NULL DEFAULT 0,
    notes TEXT
  )`);
});

// --- sqlite helpers ---
const dbAll = (sql, params = []) => new Promise((res, rej) => db.all(sql, params, (e, r) => e ? rej(e) : res(r)));
const dbRun = (sql, params = []) => new Promise((res, rej) => db.run(sql, params, function (e) { e ? rej(e) : res({ changes: this.changes, lastID: this.lastID }); }));

// --- utils ---
function isValidDateYYYYMMDD(s) { return /^\d{4}-\d{2}-\d{2}$/.test(s); }
function toNum(x, d = 0) { const n = parseFloat(x); return Number.isFinite(n) ? n : d; }
function computePnl(row) {
  const { side, qty, entry_price, exit_price, fees } = row;
  const gross = side === 'LONG' ? (exit_price - entry_price) * qty : (entry_price - exit_price) * qty;
  return gross - (fees || 0);
}
function getMonthMeta(year, monthIdx /*0-11*/) {
  const first = new Date(Date.UTC(year, monthIdx, 1));
  const last = new Date(Date.UTC(year, monthIdx + 1, 0));
  const daysInMonth = last.getUTCDate();
  const firstDow = first.getUTCDay(); // 0=Sun ... 6=Sat
  return { first, last, daysInMonth, firstDow };
}
function getISOWeekKey(yyyyMmDd){
  // returns 'YYYY-Www' (ISO week), Monday = first day
  const [Y,M,D] = yyyyMmDd.split('-').map(Number);
  const d = new Date(Date.UTC(Y, M-1, D));
  // ISO: Thursday in current week determines week year
  const dayNum = (d.getUTCDay() + 6) % 7; // 0=Mon..6=Sun
  const thursday = new Date(d); thursday.setUTCDate(d.getUTCDate() - dayNum + 3);
  const weekYear = thursday.getUTCFullYear();
  const jan4 = new Date(Date.UTC(weekYear,0,4));
  const jan4DayNum = (jan4.getUTCDay() + 6) % 7;
  const week1Start = new Date(jan4); week1Start.setUTCDate(jan4.getUTCDate() - jan4DayNum);
  const week = 1 + Math.round((d - week1Start)/ (7*24*3600*1000));
  return `${weekYear}-W${String(week).padStart(2,'0')}`;
}
function monthKey(yyyyMmDd){ return yyyyMmDd.slice(0,7); } // 'YYYY-MM'

function buildCalendar(dailyMap, year, monthIdx) {
  const { daysInMonth, firstDow } = getMonthMeta(year, monthIdx);
  const cells = [];
  for (let i = 0; i < firstDow; i++) cells.push(null);
  for (let day = 1; day <= daysInMonth; day++) {
    const dateStr = `${year}-${String(monthIdx + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
    const pnl = dailyMap.get(dateStr) || 0;
    cells.push({ dateStr, day, pnl });
  }
  while (cells.length % 7 !== 0) cells.push(null);
  const weeks = [];
  for (let i = 0; i < cells.length; i += 7) weeks.push(cells.slice(i, i + 7));
  return weeks;
}

function currencyServer(n){ const v = Number(n||0); const s = v.toFixed(2); return v>=0? ('$'+s) : ('-$'+Math.abs(v).toFixed(2)); }
function escapeHtmlServer(str){ return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;').replace(/'/g,'&#039;'); }
function metricCardServer(title, val, raw){
  const tone = typeof raw === 'number' ? (raw>0?'text-emerald-600':raw<0?'text-rose-600':'') : '';
  return "<div class='bg-white rounded-2xl shadow p-5'>"+
         "<div class='text-xs text-slate-500'>"+title+"</div>"+
         "<div class='text-2xl font-semibold mt-1 "+tone+"'>"+val+"</div>"+
         "</div>";
}

// --- File upload (CSV) ---
const upload = multer({ dest: path.join(__dirname, 'uploads') });

// Accept CSV with headers (flexible):
// Required: date, symbol, side, qty, entry, exit
// Optional: fees, notes
// Date format accepted: YYYY-MM-DD (preferred) or MM/DD/YYYY
function normalizeDate(s){
  if (!s) return null;
  s = String(s).trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  const m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{2,4})$/);
  if (m){
    let mm = parseInt(m[1],10), dd = parseInt(m[2],10), yy = parseInt(m[3],10);
    if (yy < 100) yy += 2000;
    return `${yy}-${String(mm).padStart(2,'0')}-${String(dd).padStart(2,'0')}`;
  }
  return null;
}
function normalizeSide(s){ s = String(s||'').trim().toUpperCase(); return s.startsWith('S')? 'SHORT' : 'LONG'; }

app.post('/import', upload.single('csvfile'), async (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');
  const filePath = req.file.path;
  const rows = [];
  try {
    await new Promise((resolve, reject) => {
      fs.createReadStream(filePath)
        .pipe(parse({ columns: true, skip_empty_lines: true, trim: true }))
        .on('data', rec => rows.push(rec))
        .on('end', resolve)
        .on('error', reject);
    });

    let inserted = 0, skipped = 0;
    for (const r of rows){
      // try common header variants
      const trade_date = normalizeDate(r.date || r.trade_date || r.TradeDate || r['Trade Date'] || r['Date']);
      const symbol = (r.symbol || r.Symbol || r.ticker || r.Ticker || '').toString().trim().toUpperCase();
      const side = normalizeSide(r.side || r.Side || r.direction || r.Direction);
      const qty = toNum(r.qty || r.Quantity || r.contracts || r.size, 0);
      const entry_price = toNum(r.entry || r.Entry || r.entry_price || r['Entry Price'] || r.avg_entry || r['Avg Entry']);
      const exit_price  = toNum(r.exit  || r.Exit  || r.exit_price  || r['Exit Price']  || r.avg_exit  || r['Avg Exit']);
      const fees = toNum(r.fees || r.Fees || r.commissions || r.Commissions || r['Commission'], 0);
      const notes = (r.notes || r.Notes || r.strategy || r.Strategy || '').toString();

      if (!trade_date || !symbol || !(qty>0) || !Number.isFinite(entry_price) || !Number.isFinite(exit_price)){
        skipped++; continue;
      }

      await dbRun(`INSERT INTO trades (trade_date, symbol, side, qty, entry_price, exit_price, fees, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [trade_date, symbol, side, qty, entry_price, exit_price, fees, notes]);
      inserted++;
    }

    res.redirect(`/?imported=${inserted}&skipped=${skipped}`);
  } catch (e){
    console.error(e);
    res.status(500).send('Import error: ' + e.message);
  } finally {
    fs.unlink(filePath, () => {});
  }
});

// --- Home (Dashboard + Calendar + Summaries + Import UI) ---
app.get('/', async (req, res) => {
  try {
    const now = new Date();
    const queryYear = toNum(req.query.y, now.getUTCFullYear());
    const queryMonth = toNum(req.query.m, now.getUTCMonth() + 1); // 1-12
    const year = Math.max(1970, Math.min(3000, queryYear));
    const monthIdx = Math.max(0, Math.min(11, queryMonth - 1));

    const trades = await dbAll(`SELECT id, trade_date, symbol, side, qty, entry_price, exit_price, fees, notes FROM trades ORDER BY trade_date DESC, id DESC`);
    const tradesWithPnl = trades.map(t => ({ ...t, pnl: computePnl(t) }));

    const dailyMap = new Map();
    for (const t of tradesWithPnl) dailyMap.set(t.trade_date, (dailyMap.get(t.trade_date) || 0) + t.pnl);
    const dailySorted = Array.from(dailyMap.entries()).sort((a,b)=>a[0].localeCompare(b[0])).map(([date,total])=>({date,total}));

    // Metrics
    const totalTrades = tradesWithPnl.length;
    const winners = tradesWithPnl.filter(t=>t.pnl>0);
    const losers = tradesWithPnl.filter(t=>t.pnl<0);
    const grossPnL = tradesWithPnl.reduce((a,b)=>a+b.pnl,0);
    const winRate = totalTrades ? (winners.length/totalTrades)*100 : 0;
    const avgWin = winners.length ? winners.reduce((a,b)=>a+b.pnl,0)/winners.length : 0;
    const avgLoss = losers.length ? Math.abs(losers.reduce((a,b)=>a+b.pnl,0)/losers.length) : 0;
    const expectancy = (winRate/100)*avgWin - (1 - winRate/100)*avgLoss;

    // Month
    const monthStr = `${year}-${String(monthIdx + 1).padStart(2,'0')}`;
    const mtdDaily = dailySorted.filter(d=>d.date.startsWith(monthStr));
    const mtdPnL = mtdDaily.reduce((a,b)=>a+b.total,0);
    const bestDay = dailySorted.length ? dailySorted.reduce((best,d)=> d.total>best.total?d:best, {total:-Infinity}) : null;
    const worstDay = dailySorted.length ? dailySorted.reduce((worst,d)=> d.total<worst.total?d:worst, {total:Infinity}) : null;

    // Weekly & Monthly summaries
    const weeklyMap = new Map();
    const monthlyMap = new Map();
    for (const d of dailySorted){
      const wk = getISOWeekKey(d.date);
      weeklyMap.set(wk, (weeklyMap.get(wk)||0) + d.total);
      const mk = monthKey(d.date);
      monthlyMap.set(mk, (monthlyMap.get(mk)||0) + d.total);
    }
    const weeklySummary = Array.from(weeklyMap.entries()).sort((a,b)=>a[0].localeCompare(b[0])).map(([k,v])=>({week:k,total:v}));
    const monthlySummary = Array.from(monthlyMap.entries()).sort((a,b)=>a[0].localeCompare(b[0])).map(([k,v])=>({month:k,total:v}));

    // Calendar
    const calWeeks = buildCalendar(dailyMap, year, monthIdx);
    const prev = new Date(Date.UTC(year, monthIdx - 1, 1));
    const next = new Date(Date.UTC(year, monthIdx + 1, 1));
    const prevLink = `/?y=${prev.getUTCFullYear()}&m=${prev.getUTCMonth()+1}`;
    const nextLink = `/?y=${next.getUTCFullYear()}&m=${next.getUTCMonth()+1}`;

    const weekdayHeader = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].map(d=>"<div class='text-center'>"+d+"</div>").join('');
    const calendarGrid = calWeeks.map(week => week.map(cell => {
      if(!cell) return "<div class='h-20 rounded-xl bg-slate-100'></div>";
      const pnl = Number(cell.pnl||0);
      const cls = pnl>0? 'bg-emerald-200' : (pnl<0? 'bg-rose-200' : 'bg-slate-100');
      const tone = pnl>0? 'text-emerald-700' : (pnl<0? 'text-rose-700' : 'text-slate-500');
      const pnlTxt = pnl ? ((pnl>=0?'+':'')+pnl.toFixed(2)) : '';
      return "<div class='h-20 rounded-xl "+cls+" p-2 flex flex-col justify-between'>"+
             "<div class='text-[10px] text-slate-600'>"+cell.dateStr+"</div>"+
             "<div class='text-right text-sm font-mono "+tone+"'>"+pnlTxt+"</div>"+
             "</div>";
    }).join('')).join('');

    const html = `<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8' />
  <meta name='viewport' content='width=device-width, initial-scale=1' />
  <title>TraderX • Dashboard</title>
  <script src='https://cdn.tailwindcss.com'></script>
  <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
</head>
<body class='bg-slate-50 text-slate-900'>
  <div class='max-w-7xl mx-auto p-6 space-y-6'>
    <header class='flex items-center justify-between'>
      <h1 class='text-2xl md:text-3xl font-bold'>TraderX</h1>
      <nav class='flex gap-4 text-sm'>
        <a class='underline' href='#add'>Add Trade</a>
        <a class='underline' href='/api/trades'>API</a>
      </nav>
    </header>

    <section class='grid md:grid-cols-4 gap-4'>
      ${metricCardServer('Total Trades', String(totalTrades))}
      ${metricCardServer('Win Rate', winRate.toFixed(1)+'%')}
      ${metricCardServer('Gross PnL', currencyServer(grossPnL), grossPnL)}
      ${metricCardServer('Expectancy/trade', currencyServer(expectancy), expectancy)}
    </section>

    <section class='grid lg:grid-cols-3 gap-6'>
      <div class='lg:col-span-2 bg-white rounded-2xl shadow p-5'>
        <div class='flex items-center justify-between mb-3'>
          <h2 class='text-xl font-semibold'>Calendar PnL — ${year}-${String(monthIdx + 1).padStart(2,'0')}</h2>
          <div class='flex items-center gap-2'>
            <a class='px-3 py-1 rounded-xl border' href='${prevLink}'>◀ Prev</a>
            <a class='px-3 py-1 rounded-xl border' href='${nextLink}'>Next ▶</a>
          </div>
        </div>
        <div class='grid grid-cols-7 text-xs text-slate-500 mb-2'>${weekdayHeader}</div>
        <div class='grid grid-cols-7 gap-2'>${calendarGrid}</div>
        <div class='mt-3 text-xs text-slate-500 flex items-center gap-4'>
          <span><span class='inline-block w-3 h-3 rounded-sm align-middle bg-emerald-200'></span> Profit</span>
          <span><span class='inline-block w-3 h-3 rounded-sm align-middle bg-rose-200'></span> Loss</span>
          <span><span class='inline-block w-3 h-3 rounded-sm align-middle bg-slate-100'></span> No trades</span>
        </div>
      </div>

      <div class='bg-white rounded-2xl shadow p-5'>
        <h2 class='text-xl font-semibold mb-3'>MTD & Highlights</h2>
        <ul class='text-sm space-y-2'>
          <li><span class='text-slate-500'>Month-to-date PnL:</span> <span class='font-mono ${mtdPnL>=0?'text-emerald-600':'text-rose-600'}'>${currencyServer(mtdPnL)}</span></li>
          <li><span class='text-slate-500'>Best day:</span> ${bestDay ? `${bestDay.date} — <span class='font-mono text-emerald-600'>${currencyServer(bestDay.total)}</span>` : '—'}</li>
          <li><span class='text-slate-500'>Worst day:</span> ${worstDay ? `${worstDay.date} — <span class='font-mono text-rose-600'>${currencyServer(worstDay.total)}</span>` : '—'}</li>
          <li><span class='text-slate-500'>Avg win / Avg loss (per trade):</span> <span class='font-mono'>${currencyServer(avgWin)} / -${currencyServer(avgLoss)}</span></li>
        </ul>
        <div class='mt-4'>
          <canvas id='pnlChart' height='130'></canvas>
        </div>
      </div>
    </section>

    <section class='grid lg:grid-cols-3 gap-6'>
      <!-- Weekly Summary -->
      <div class='bg-white rounded-2xl shadow p-5'>
        <h2 class='text-xl font-semibold mb-3'>Weekly PnL (ISO weeks)</h2>
        <div class='overflow-x-auto'>
          <table class='min-w-full text-sm'>
            <thead><tr class='text-left border-b'><th class='py-2 pr-4'>Week</th><th class='py-2'>Total</th></tr></thead>
            <tbody>
              ${weeklySummary.length? weeklySummary.map(w=> (
                "<tr class='border-b last:border-b-0'>"+
                "<td class='py-2 pr-4'>"+w.week+"</td>"+
                "<td class='py-2 font-mono "+(w.total>=0?'text-emerald-600':'text-rose-600')+"'>"+w.total.toFixed(2)+"</td>"+
                "</tr>"
              )).join('') : "<tr><td class='py-2' colspan='2'>No data yet.</td></tr>"}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Monthly Summary -->
      <div class='bg-white rounded-2xl shadow p-5'>
        <h2 class='text-xl font-semibold mb-3'>Monthly PnL</h2>
        <div class='overflow-x-auto'>
          <table class='min-w-full text-sm'>
            <thead><tr class='text-left border-b'><th class='py-2 pr-4'>Month</th><th class='py-2'>Total</th></tr></thead>
            <tbody>
              ${monthlySummary.length? monthlySummary.map(m=> (
                "<tr class='border-b last:border-b-0'>"+
                "<td class='py-2 pr-4'>"+m.month+"</td>"+
                "<td class='py-2 font-mono "+(m.total>=0?'text-emerald-600':'text-rose-600')+"'>"+m.total.toFixed(2)+"</td>"+
                "</tr>"
              )).join('') : "<tr><td class='py-2' colspan='2'>No data yet.</td></tr>"}
            </tbody>
          </table>
        </div>
      </div>

      <!-- CSV Import -->
      <div class='bg-white rounded-2xl shadow p-5'>
        <h2 class='text-xl font-semibold mb-3'>CSV Import</h2>
        <form method='POST' action='/import' enctype='multipart/form-data' class='space-y-3'>
          <input type='file' name='csvfile' accept='.csv' class='block w-full text-sm'>
          <button class='px-4 py-2 rounded-xl shadow bg-slate-900 text-white'>Upload & Import</button>
        </form>
        <p class='text-xs text-slate-500 mt-3'>Headers accepted: <code>date, trade_date, symbol, side, qty, entry, exit, fees, notes</code> (flexible variants supported). Dates: <code>YYYY-MM-DD</code> or <code>MM/DD/YYYY</code>.</p>
        ${req.query.imported? `<p class='text-sm mt-2'>Imported: <b>${req.query.imported}</b>, Skipped: <b>${req.query.skipped||0}</b></p>`:''}
      </div>
    </section>

    <!-- Add Trade + Daily table -->
    <section class='grid md:grid-cols-2 gap-6'>
      <div id='add' class='bg-white rounded-2xl shadow p-5'>
        <h2 class='text-xl font-semibold mb-3'>Add Trade</h2>
        <form method='POST' action='/trades' class='grid grid-cols-2 gap-3'>
          <div class='col-span-2'>
            <label class='block text-xs text-slate-600'>Date</label>
            <input name='trade_date' type='date' required class='w-full border rounded-xl p-2'>
          </div>
          <div>
            <label class='block text-xs text-slate-600'>Symbol</label>
            <input name='symbol' placeholder='ESU5' required class='w-full border rounded-xl p-2'>
          </div>
          <div>
            <label class='block text-xs text-slate-600'>Side</label>
            <select name='side' class='w-full border rounded-xl p-2'><option>LONG</option><option>SHORT</option></select>
          </div>
          <div>
            <label class='block text-xs text-slate-600'>Qty</label>
            <input name='qty' type='number' min='1' value='1' required class='w-full border rounded-xl p-2'>
          </div>
          <div>
            <label class='block text-xs text-slate-600'>Entry</label>
            <input name='entry_price' type='number' step='0.01' required class='w-full border rounded-xl p-2'>
          </div>
          <div>
            <label class='block text-xs text-slate-600'>Exit</label>
            <input name='exit_price' type='number' step='0.01' required class='w-full border rounded-xl p-2'>
          </div>
          <div class='col-span-2'>
            <label class='block text-xs text-slate-600'>Fees</label>
            <input name='fees' type='number' step='0.01' value='0' class='w-full border rounded-xl p-2'>
          </div>
          <div class='col-span-2'>
            <label class='block text-xs text-slate-600'>Notes</label>
            <textarea name='notes' rows='2' class='w-full border rounded-xl p-2' placeholder='setup, reason, etc.'></textarea>
          </div>
          <div class='col-span-2 flex gap-2'>
            <button class='px-4 py-2 rounded-xl shadow bg-slate-900 text-white'>Save</button>
            <a href='/' class='px-4 py-2 rounded-xl border'>Cancel</a>
          </div>
        </form>
      </div>

      <div class='bg-white rounded-2xl shadow p-5'>
        <h2 class='text-xl font-semibold mb-3'>Daily PnL</h2>
        <div class='overflow-x-auto'>
          <table class='min-w-full text-sm'>
            <thead><tr class='text-left border-b'><th class='py-2 pr-4'>Date</th><th class='py-2'>Total PnL</th></tr></thead>
            <tbody>
              ${dailySorted.length ? dailySorted.map(d => (
                "<tr class='border-b last:border-b-0'>"+
                "<td class='py-2 pr-4'>"+d.date+"</td>"+
                "<td class='py-2 font-mono "+(d.total>=0?'text-emerald-600':'text-rose-600')+"'>"+d.total.toFixed(2)+"</td>"+
                "</tr>"
              )).join('') : "<tr><td class='py-2' colspan='2'>No data yet.</td></tr>"}
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <section class='bg-white rounded-2xl shadow p-5'>
      <h2 class='text-xl font-semibold mb-3'>Trades</h2>
      <div class='overflow-x-auto'>
        <table class='min-w-full text-sm'>
          <thead>
            <tr class='text-left border-b'>
              <th class='py-2 pr-4'>Date</th>
              <th class='py-2 pr-4'>Symbol</th>
              <th class='py-2 pr-4'>Side</th>
              <th class='py-2 pr-4'>Qty</th>
              <th class='py-2 pr-4'>Entry</th>
              <th class='py-2 pr-4'>Exit</th>
              <th class='py-2 pr-4'>Fees</th>
              <th class='py-2 pr-4'>PnL</th>
              <th class='py-2 pr-4'>Notes</th>
              <th class='py-2'>Actions</th>
            </tr>
          </thead>
          <tbody>
          ${tradesWithPnl.length ? tradesWithPnl.map(t => (
            "<tr class='border-b last:border-b-0 align-top'>"+
            "<td class='py-2 pr-4'>"+t.trade_date+"</td>"+
            "<td class='py-2 pr-4 font-mono'>"+t.symbol+"</td>"+
            "<td class='py-2 pr-4'>"+t.side+"</td>"+
            "<td class='py-2 pr-4'>"+t.qty+"</td>"+
            "<td class='py-2 pr-4'>"+Number(t.entry_price).toFixed(2)+"</td>"+
            "<td class='py-2 pr-4'>"+Number(t.exit_price).toFixed(2)+"</td>"+
            "<td class='py-2 pr-4'>"+Number(t.fees||0).toFixed(2)+"</td>"+
            "<td class='py-2 pr-4 font-mono "+(t.pnl>=0?'text-emerald-600':'text-rose-600')+"'>"+t.pnl.toFixed(2)+"</td>"+
            "<td class='py-2 pr-4 whitespace-pre-wrap'>"+(t.notes ? escapeHtmlServer(t.notes) : '')+"</td>"+
            "<td class='py-2'>"+
              "<form method='POST' action='/trades/"+t.id+"/delete' onsubmit='return confirm(\"Delete this trade?\");'>"+
                "<button class='text-rose-700 underline'>Delete</button>"+
              "</form>"+
            "</td>"+
            "</tr>"
          )).join('') : "<tr><td class='py-2' colspan='10'>No trades yet. Add your first trade above.</td></tr>"}
          </tbody>
        </table>
      </div>
    </section>

    <footer class='text-xs text-slate-500 text-center py-6'>TraderX • Local only • v0.3 (CSV + Weekly/Monthly + Cloud‑ready)</footer>
  </div>

  <script>
    // Chart: Daily PnL over time
    const labels = ${JSON.stringify(dailySorted.map(d=>d.date))};
    const data = ${JSON.stringify(dailySorted.map(d=>Number(d.total.toFixed(2))))};
    const ctx = document.getElementById('pnlChart');
    if (ctx && labels.length){
      new Chart(ctx, { type: 'bar', data: { labels, datasets: [{ label:'Daily PnL', data }] }, options:{ responsive:true, scales:{ y:{ beginAtZero:true }}}});
    }
  </script>
</body>
</html>`;

    res.status(200).send(html);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// --- CRUD ---
app.post('/trades', async (req, res) => {
  try {
    const { trade_date, symbol, side, qty, entry_price, exit_price, fees = 0, notes = '' } = req.body;
    if (!isValidDateYYYYMMDD(trade_date)) throw new Error('Invalid date format. Use YYYY-MM-DD.');
    if (!symbol || (side !== 'LONG' && side !== 'SHORT')) throw new Error('Invalid symbol or side');
    const qtyNum = parseInt(qty, 10);
    const entryNum = toNum(entry_price);
    const exitNum = toNum(exit_price);
    const feesNum = toNum(fees, 0);
    if (!(qtyNum > 0) || !Number.isFinite(entryNum) || !Number.isFinite(exitNum)) throw new Error('Invalid numbers');

    await dbRun(`INSERT INTO trades (trade_date, symbol, side, qty, entry_price, exit_price, fees, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [trade_date, symbol.trim().toUpperCase(), side, qtyNum, entryNum, exitNum, feesNum, notes]);
    res.redirect('back');
  } catch (e) {
    console.error(e);
    res.status(400).send('Bad request: ' + e.message);
  }
});

app.post('/trades/:id/delete', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!id) throw new Error('Invalid ID');
    await dbRun(`DELETE FROM trades WHERE id = ?`, [id]);
    res.redirect('back');
  } catch (e) {
    console.error(e);
    res.status(400).send('Bad request: ' + e.message);
  }
});

// --- APIs ---
app.get('/api/trades', async (_req, res) => {
  try {
    const rows = await dbAll(`SELECT * FROM trades ORDER BY trade_date DESC, id DESC`);
    res.json(rows.map(r => ({ ...r, pnl: computePnl(r) })));
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/daily-pnl', async (_req, res) => {
  try {
    const rows = await dbAll(`SELECT trade_date, SUM(CASE WHEN side='LONG' THEN (exit_price - entry_price) * qty WHEN side='SHORT' THEN (entry_price - exit_price) * qty END - fees) AS total FROM trades GROUP BY trade_date ORDER BY trade_date`);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/weekly-pnl', async (_req, res) => {
  try {
    const rows = await dbAll(`SELECT trade_date, SUM(CASE WHEN side='LONG' THEN (exit_price - entry_price) * qty WHEN side='SHORT' THEN (entry_price - exit_price) * qty END - fees) AS total FROM trades GROUP BY trade_date ORDER BY trade_date`);
    const weekly = {};
    for (const r of rows){ const wk = getISOWeekKey(r.trade_date); weekly[wk] = (weekly[wk]||0) + (r.total||0); }
    res.json(Object.entries(weekly).sort((a,b)=>a[0].localeCompare(b[0])).map(([week,total])=>({week,total})));
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/monthly-pnl', async (_req, res) => {
  try {
    const rows = await dbAll(`SELECT trade_date, SUM(CASE WHEN side='LONG' THEN (exit_price - entry_price) * qty WHEN side='SHORT' THEN (entry_price - exit_price) * qty END - fees) AS total FROM trades GROUP BY trade_date ORDER BY trade_date`);
    const monthly = {};
    for (const r of rows){ const mk = monthKey(r.trade_date); monthly[mk] = (monthly[mk]||0) + (r.total||0); }
    res.json(Object.entries(monthly).sort((a,b)=>a[0].localeCompare(b[0])).map(([month,total])=>({month,total})));
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.listen(PORT, () => console.log(`TraderX running at http://localhost:${PORT}`));
