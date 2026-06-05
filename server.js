const express = require('express');
const axios = require('axios');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : true }));
app.use(express.json({ limit: '1mb' }));

const TELEGRAM_TOKEN   = process.env.TELEGRAM_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const JWT_SECRET       = process.env.JWT_SECRET || 'CHANGE_ME_IN_RENDER_ENV';
const DATA_FILE        = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const DEFAULT_INTERVAL = Math.max(30, Number(process.env.DEFAULT_CHECK_INTERVAL_SEC || 60));
const MIN_INTERVAL     = Math.max(20, Number(process.env.MIN_CHECK_INTERVAL_SEC || 30));

const users = {};
const monitors = {};

function safeMonitor(m) {
  const { timers, checker, lastHtml, ...clean } = m;
  return clean;
}

function saveData() {
  const payload = {
    users,
    monitors: Object.fromEntries(Object.entries(monitors).map(([id, m]) => [id, safeMonitor(m)]))
  };
  fs.writeFileSync(DATA_FILE, JSON.stringify(payload, null, 2));
}

function loadData() {
  if (!fs.existsSync(DATA_FILE)) return;
  try {
    const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    Object.assign(users, data.users || {});
    for (const [id, m] of Object.entries(data.monitors || {})) {
      monitors[id] = { ...m, timers: [], checker: null };
    }
    console.log(`[Data] Loaded ${Object.keys(users).length} users and ${Object.keys(monitors).length} monitors`);
  } catch (e) {
    console.error('[Data] Could not load data file:', e.message);
  }
}

async function seedAdmin() {
  const existing = Object.values(users).find(u => u.username?.toLowerCase() === 'admin');
  if (existing) return;
  const adminPass = process.env.ADMIN_PASSWORD || 'ChangeMe123!';
  const hash = await bcrypt.hash(adminPass, 12);
  users['admin-001'] = {
    id: 'admin-001',
    username: 'admin',
    email: process.env.ADMIN_EMAIL || 'admin@ticketsnap.app',
    passwordHash: hash,
    role: 'admin',
    createdAt: new Date().toISOString()
  };
  saveData();
  console.log('[Auth] Admin account created — username: admin');
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  next();
}

async function sendTelegram(message) {
  if (!TELEGRAM_TOKEN || !TELEGRAM_CHAT_ID) return;
  try {
    await axios.post(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, {
      chat_id: TELEGRAM_CHAT_ID,
      text: message,
      parse_mode: 'HTML',
      disable_web_page_preview: false
    });
  } catch (e) {
    console.error('Telegram error:', e.message);
  }
}

function normalizeText(html = '') {
  return String(html)
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .toLowerCase();
}

const DEFAULT_POSITIVE_KEYWORDS = [
  'buy tickets', 'find tickets', 'get tickets', 'unlock tickets', 'select tickets',
  'tickets are available', 'on sale now', 'available now', 'choose seats', 'seat map'
];
const DEFAULT_NEGATIVE_KEYWORDS = [
  'tickets are not currently available', 'currently not available', 'sold out',
  'not on sale', 'sale starts', 'presale starts', 'please check back', 'event is not available',
  'join the waiting room', 'you are in line', 'queue', 'waiting room'
];

function hashContent(input = '') {
  return crypto.createHash('sha256').update(String(input).slice(0, 750000)).digest('hex');
}

function addActivity(m, type, message) {
  m.activity = Array.isArray(m.activity) ? m.activity.slice(-29) : [];
  m.activity.push({ at: new Date().toISOString(), type, message });
}

function summarizePage(html = '') {
  const text = normalizeText(html);
  const snippets = [];
  const watchTerms = [...DEFAULT_POSITIVE_KEYWORDS, ...DEFAULT_NEGATIVE_KEYWORDS, 'presale', 'onsale', 'sold out', 'unavailable'];
  for (const term of watchTerms) {
    const idx = text.indexOf(term);
    if (idx >= 0) snippets.push(text.slice(Math.max(0, idx - 90), idx + term.length + 120));
    if (snippets.length >= 5) break;
  }
  return [...new Set(snippets)];
}

function analyzeAvailability(html, positiveKeywords = DEFAULT_POSITIVE_KEYWORDS, negativeKeywords = DEFAULT_NEGATIVE_KEYWORDS) {
  const text = normalizeText(html);
  const negativeHit = negativeKeywords.find(k => text.includes(k.toLowerCase()));
  const positiveHit = positiveKeywords.find(k => text.includes(k.toLowerCase()));
  if (positiveHit && !negativeHit) return { available: true, reason: `Matched: ${positiveHit}` };
  if (positiveHit && negativeHit) return { available: false, reason: `Mixed signal: ${positiveHit}; also found ${negativeHit}` };
  if (negativeHit) return { available: false, reason: `Not available signal: ${negativeHit}` };
  return { available: false, reason: 'No availability keyword found' };
}

async function checkAvailability(id, manual = false) {
  const m = monitors[id];
  if (!m || m.status === 'stopped') return null;
  try {
    const r = await axios.get(m.ticketUrl, {
      timeout: 12000,
      maxRedirects: 5,
      headers: {
        'User-Agent': 'Mozilla/5.0 TicketSnap private availability checker',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache'
      },
      validateStatus: s => s >= 200 && s < 500
    });
    const html = typeof r.data === 'string' ? r.data : JSON.stringify(r.data);
    const result = analyzeAvailability(html, m.positiveKeywords, m.negativeKeywords);
    const digest = hashContent(html);
    const pageChanged = Boolean(m.lastContentHash && m.lastContentHash !== digest);
    const nowIso = new Date().toISOString();
    m.lastCheckedAt = nowIso;
    m.lastHttpStatus = r.status;
    m.lastCheckReason = result.reason;
    m.lastContentHash = digest;
    m.lastSignals = summarizePage(html);
    m.pageChangeCount = (m.pageChangeCount || 0) + (pageChanged ? 1 : 0);
    m.checkCount = (m.checkCount || 0) + 1;
    m.error = null;

    if (manual) addActivity(m, 'manual-check', `Manual check completed: ${result.reason}`);
    if (pageChanged) {
      m.lastChangedAt = nowIso;
      addActivity(m, 'page-change', 'Official event page content changed. Review the event page manually.');
      if (m.alertOnPageChange !== false) {
        await sendTelegram(`🔎 <b>TicketSnap page change detected</b>\n\n<b>${m.eventName}</b>\nReason: ${result.reason}\n\n👉 <a href="${m.ticketUrl}">Open official ticket page</a>`);
      }
    }

    if (result.available && m.status !== 'available') {
      m.status = 'available';
      m.availableAt = nowIso;
      addActivity(m, 'availability', result.reason);
      await sendTelegram(`🎟 <b>POSSIBLE TICKET AVAILABILITY DETECTED</b>\n\n<b>${m.eventName}</b>\n${result.reason}\n\n👉 <a href="${m.ticketUrl}">Open official ticket page now</a>`);
    } else if (!result.available && m.status !== 'stopped') {
      // Important: sale time alone is NOT availability.
      // Keep monitoring until the official page check finds real positive availability signals.
      m.status = 'checking';
      m.availableAt = null;
    }
    saveData();
    return { ...result, httpStatus: r.status, manual, pageChanged, signals: m.lastSignals };
  } catch (e) {
    m.lastCheckedAt = new Date().toISOString();
    m.lastCheckReason = 'Check failed';
    m.error = e.message;
    addActivity(m, 'error', e.message);
    saveData();
    return { available: false, reason: e.message, manual };
  }
}

function scheduleAlerts(id) {
  const m = monitors[id];
  if (!m) return;
  const saleMs = new Date(m.saleTime).getTime();
  const now = Date.now();
  m.timers?.forEach(t => clearTimeout(t));
  m.timers = [];
  const add = (offsetMs, fn) => {
    const delay = saleMs - offsetMs - now;
    if (delay > 0) m.timers.push(setTimeout(fn, delay));
  };
  add(15 * 60 * 1000, () => sendTelegram(`🕒 <b>15 minutes to go</b>\n\n<b>${m.eventName}</b> tickets may open soon. Open your browser and be ready.\n\n👉 <a href="${m.ticketUrl}">Official event page</a>`));
  add(5 * 60 * 1000, () => sendTelegram(`⏰ <b>5 minutes to go!</b>\n\n<b>${m.eventName}</b> tickets may open in 5 minutes.\n\n👉 <a href="${m.ticketUrl}">Get ready</a>`));
  add(1 * 60 * 1000, () => sendTelegram(`🔔 <b>1 minute!</b>\n\n<b>${m.eventName}</b> — be ready on your screen.\n\n👉 <a href="${m.ticketUrl}">Stand by</a>`));
  add(0, async () => {
    if (monitors[id] && monitors[id].status !== 'available' && monitors[id].status !== 'stopped') {
      // Sale time reached is only a reminder, not proof that tickets are available.
      monitors[id].status = 'checking';
      monitors[id].saleTimeReached = true;
    }
    saveData();
    await sendTelegram(`🎟 <b>SALE TIME REACHED</b>\n\n<b>${m.eventName}</b>\nThis is only the scheduled sale time. TicketSnap will still wait for page signals before marking tickets as available.\n\n👉 <a href="${m.ticketUrl}">Open official ticket page</a>`);
    checkAvailability(id, true);
  });
  if (saleMs <= now && m.status !== 'available' && m.status !== 'stopped') {
    m.status = 'checking';
    m.saleTimeReached = true;
  }
}

function startAvailabilityChecker(id) {
  const m = monitors[id];
  if (!m || !m.availabilityCheck || m.status === 'stopped') return;
  if (m.checker) clearInterval(m.checker);
  const tick = () => {
    checkAvailability(id, false);
    const fresh = monitors[id];
    if (!fresh || fresh.status === 'stopped') return;
    const saleMs = new Date(fresh.saleTime).getTime();
    const minutesToSale = (saleMs - Date.now()) / 60000;
    const configured = Math.max(MIN_INTERVAL, Number(fresh.checkIntervalSec || DEFAULT_INTERVAL));
    const adaptive = minutesToSale <= 10 ? Math.min(configured, 30) : configured;
    clearInterval(fresh.checker);
    fresh.checker = setInterval(tick, adaptive * 1000);
  };
  checkAvailability(id, true);
  const intervalSec = Math.max(MIN_INTERVAL, Number(m.checkIntervalSec || DEFAULT_INTERVAL));
  m.checker = setInterval(tick, intervalSec * 1000);
}

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const user = Object.values(users).find(u => u.username?.toLowerCase() === username.toLowerCase() || u.email?.toLowerCase() === username.toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ error: 'Invalid username or password' });
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username: user.username, email: user.email, role: user.role } });
});

app.post('/api/auth/signup', requireAuth, requireAdmin, async (req, res) => {
  const { username, email, password, role } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'username, email and password required' });
  const exists = Object.values(users).find(u => u.username?.toLowerCase() === username.toLowerCase() || u.email?.toLowerCase() === email.toLowerCase());
  if (exists) return res.status(409).json({ error: 'Username or email already in use' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const id = uuidv4();
  users[id] = { id, username, email, passwordHash: await bcrypt.hash(password, 12), role: role === 'admin' ? 'admin' : 'user', createdAt: new Date().toISOString() };
  saveData();
  res.status(201).json({ message: 'User created', id, username, role: users[id].role });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = users[req.user.id];
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, username: user.username, email: user.email, role: user.role });
});

app.get('/api/auth/users', requireAuth, requireAdmin, (req, res) => {
  res.json(Object.values(users).map(u => ({ id: u.id, username: u.username, email: u.email, role: u.role, createdAt: u.createdAt })));
});

app.delete('/api/auth/users/:id', requireAuth, requireAdmin, (req, res) => {
  if (req.params.id === 'admin-001') return res.status(400).json({ error: 'Cannot delete the main admin account' });
  if (!users[req.params.id]) return res.status(404).json({ error: 'User not found' });
  delete users[req.params.id];
  saveData();
  res.json({ ok: true });
});

app.post('/api/monitor/start', requireAuth, async (req, res) => {
  const { eventName, ticketUrl, saleTime, availabilityCheck = true, checkIntervalSec, positiveKeywords, negativeKeywords, alertOnPageChange = true, notes = '' } = req.body;
  if (!eventName || !ticketUrl || !saleTime) return res.status(400).json({ error: 'eventName, ticketUrl and saleTime required' });
  if (!/^https?:\/\//i.test(ticketUrl)) return res.status(400).json({ error: 'ticketUrl must start with http or https' });
  const id = uuidv4();
  monitors[id] = {
    id, eventName, ticketUrl, saleTime,
    status: availabilityCheck ? 'checking' : 'watching',
    ownerId: req.user.id,
    availabilityCheck: Boolean(availabilityCheck),
    checkIntervalSec: Math.max(MIN_INTERVAL, Number(checkIntervalSec || DEFAULT_INTERVAL)),
    positiveKeywords: Array.isArray(positiveKeywords) && positiveKeywords.length ? positiveKeywords : DEFAULT_POSITIVE_KEYWORDS,
    negativeKeywords: Array.isArray(negativeKeywords) && negativeKeywords.length ? negativeKeywords : DEFAULT_NEGATIVE_KEYWORDS,
    timers: [], checker: null,
    createdAt: new Date().toISOString(),
    checkCount: 0,
    pageChangeCount: 0,
    alertOnPageChange: Boolean(alertOnPageChange),
    notes: String(notes || '').slice(0, 500),
    activity: []
  };
  addActivity(monitors[id], 'created', 'Monitor created and legitimate availability checks started.');
  scheduleAlerts(id);
  startAvailabilityChecker(id);
  saveData();
  await sendTelegram(`👀 <b>Monitor started</b>\n\nEvent: <b>${eventName}</b>\nSale: <b>${new Date(saleTime).toLocaleString('en-PH', { timeZone: 'Asia/Manila' })} PHT</b>\nAvailability check: <b>${availabilityCheck ? 'ON' : 'OFF'}</b>\nLink: <a href="${ticketUrl}">${ticketUrl}</a>`);
  res.json({ id, status: monitors[id].status });
});

app.post('/api/monitor/check-now', requireAuth, async (req, res) => {
  const { id } = req.body;
  const m = monitors[id];
  if (!m) return res.status(404).json({ error: 'Not found' });
  if (m.ownerId !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const result = await checkAvailability(id, true);
  res.json({ ok: true, result, monitor: safeMonitor(monitors[id]) });
});

app.post('/api/monitor/stop', requireAuth, (req, res) => {
  const { id } = req.body;
  const m = monitors[id];
  if (!m) return res.status(404).json({ error: 'Not found' });
  if (m.ownerId !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  m.timers?.forEach(t => clearTimeout(t));
  if (m.checker) clearInterval(m.checker);
  m.status = 'stopped';
  saveData();
  res.json({ ok: true });
});

app.get('/api/monitor/:id', requireAuth, (req, res) => {
  const m = monitors[req.params.id];
  if (!m) return res.status(404).json({ error: 'Not found' });
  if (m.ownerId !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  res.json(safeMonitor(m));
});

app.get('/api/monitors', requireAuth, (req, res) => {
  res.json(Object.values(monitors).filter(m => req.user.role === 'admin' || m.ownerId === req.user.id).map(safeMonitor));
});


app.post('/api/monitor/analyze-url', requireAuth, async (req, res) => {
  const { ticketUrl, positiveKeywords, negativeKeywords } = req.body;
  if (!ticketUrl || !/^https?:\/\//i.test(ticketUrl)) return res.status(400).json({ error: 'Valid ticketUrl required' });
  try {
    const r = await axios.get(ticketUrl, { timeout: 12000, maxRedirects: 5, validateStatus: s => s >= 200 && s < 500 });
    const html = typeof r.data === 'string' ? r.data : JSON.stringify(r.data);
    const result = analyzeAvailability(html,
      Array.isArray(positiveKeywords) && positiveKeywords.length ? positiveKeywords : DEFAULT_POSITIVE_KEYWORDS,
      Array.isArray(negativeKeywords) && negativeKeywords.length ? negativeKeywords : DEFAULT_NEGATIVE_KEYWORDS
    );
    res.json({ ok: true, httpStatus: r.status, result, signals: summarizePage(html) });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.get('/api/simulator/queue-lessons', requireAuth, (req, res) => {
  res.json({
    ok: true,
    note: 'Educational simulator only. Do not use against real ticketing systems.',
    weakPatterns: [
      { name: 'Client-side queue flag', lesson: 'Never trust browser-only queue state. Enforce access server-side.' },
      { name: 'Predictable token', lesson: 'Use signed, expiring, non-guessable tokens generated server-side.' },
      { name: 'Launch race condition', lesson: 'Keep inventory endpoints closed until queue enforcement is active.' },
      { name: 'Cookie-only position', lesson: 'Bind queue state to validated server records, not editable client cookies.' }
    ],
    securePatterns: [
      'Signed queue token verified before inventory/checkout access',
      'Rate limiting and bot detection that does not expose bypass paths',
      'Server-side sale-state gate switched on before public launch',
      'Monitoring and audit logs for abnormal traffic'
    ]
  });
});

app.get('/', (req, res) => res.json({ ok: true, service: 'TicketSnap', availabilityChecker: true, safeMode: true }));

loadData();
seedAdmin().then(() => {
  for (const id of Object.keys(monitors)) {
    if (monitors[id].status !== 'stopped') {
      scheduleAlerts(id);
      startAvailabilityChecker(id);
    }
  }
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => console.log(`TicketSnap on :${PORT}`));
});
