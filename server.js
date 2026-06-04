const express = require('express');
const axios = require('axios');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json());

const TELEGRAM_TOKEN   = process.env.TELEGRAM_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const JWT_SECRET       = process.env.JWT_SECRET;

// ─── In-memory stores (persist across requests, reset on redeploy) ───────────
// For production you'd swap these for a real DB like Supabase or PlanetScale.
const users    = {};   // { id: { id, username, email, passwordHash, role } }
const monitors = {};   // { id: { ...monitorData, timers, ownerId } }

// ─── Seed admin account on startup ───────────────────────────────────────────
async function seedAdmin() {
  const adminPass = process.env.ADMIN_PASSWORD || 'ChangeMe123!';
  const hash = await bcrypt.hash(adminPass, 12);
  const id = 'admin-001';
  users[id] = {
    id,
    username: 'admin',
    email: process.env.ADMIN_EMAIL || 'admin@ticketsnap.app',
    passwordHash: hash,
    role: 'admin',
    createdAt: new Date().toISOString()
  };
  console.log(`[Auth] Admin account ready — username: admin`);
}
seedAdmin();

// ─── Middleware: verify JWT ───────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const payload = jwt.verify(header.split(' ')[1], JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });

  const user = Object.values(users).find(
    u => u.username.toLowerCase() === username.toLowerCase() ||
         u.email.toLowerCase() === username.toLowerCase()
  );

  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    // Same message for both cases — don't reveal which field was wrong
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({
    token,
    user: { id: user.id, username: user.username, email: user.email, role: user.role }
  });
});

// POST /api/auth/signup   (admin can create accounts; or open signup if you prefer)
app.post('/api/auth/signup', requireAuth, requireAdmin, async (req, res) => {
  const { username, email, password, role } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: 'username, email and password required' });

  const exists = Object.values(users).find(
    u => u.username.toLowerCase() === username.toLowerCase() ||
         u.email.toLowerCase() === email.toLowerCase()
  );
  if (exists) return res.status(409).json({ error: 'Username or email already in use' });

  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const hash = await bcrypt.hash(password, 12);
  const id = uuidv4();
  users[id] = {
    id, username, email,
    passwordHash: hash,
    role: role === 'admin' ? 'admin' : 'user',
    createdAt: new Date().toISOString()
  };

  res.status(201).json({ message: 'User created', id, username, role: users[id].role });
});

// GET /api/auth/me
app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = users[req.user.id];
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, username: user.username, email: user.email, role: user.role });
});

// GET /api/auth/users  (admin only)
app.get('/api/auth/users', requireAuth, requireAdmin, (req, res) => {
  const list = Object.values(users).map(u => ({
    id: u.id, username: u.username, email: u.email, role: u.role, createdAt: u.createdAt
  }));
  res.json(list);
});

// DELETE /api/auth/users/:id  (admin only)
app.delete('/api/auth/users/:id', requireAuth, requireAdmin, (req, res) => {
  if (req.params.id === 'admin-001')
    return res.status(400).json({ error: 'Cannot delete the main admin account' });
  if (!users[req.params.id]) return res.status(404).json({ error: 'User not found' });
  delete users[req.params.id];
  res.json({ ok: true });
});

// ─── TELEGRAM ────────────────────────────────────────────────────────────────
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

// ─── MONITOR ROUTES (auth required) ──────────────────────────────────────────

function scheduleAlerts(id, { eventName, ticketUrl, saleTime }) {
  const saleMs = new Date(saleTime).getTime();
  const now = Date.now();
  const timers = [];

  const add = (offsetMs, fn) => {
    const delay = saleMs - offsetMs - now;
    if (delay > 0) timers.push(setTimeout(fn, delay));
  };

  add(5 * 60 * 1000, () => sendTelegram(
    `⏰ <b>5 minutes to go!</b>\n\n<b>${eventName}</b> tickets open in 5 minutes.\n\n👉 <a href="${ticketUrl}">Get ready</a>`
  ));
  add(1 * 60 * 1000, () => sendTelegram(
    `🔔 <b>1 minute!</b>\n\n<b>${eventName}</b> — be on your screen NOW.\n\n👉 <a href="${ticketUrl}">Stand by</a>`
  ));
  add(0, async () => {
    monitors[id].status = 'live';
    await sendTelegram(
      `🎟 <b>TICKETS ARE LIVE!</b>\n\n<b>${eventName}</b>\n\n👉 <a href="${ticketUrl}">BUY NOW</a>\n\n⚡ Go go go!`
    );
  });

  // If sale time already passed, mark live immediately
  if (saleMs <= now) monitors[id].status = 'live';

  monitors[id].timers = timers;
}

app.post('/api/monitor/start', requireAuth, async (req, res) => {
  const { eventName, ticketUrl, saleTime } = req.body;
  if (!eventName || !ticketUrl || !saleTime)
    return res.status(400).json({ error: 'eventName, ticketUrl and saleTime required' });

  const id = uuidv4();
  monitors[id] = { id, eventName, ticketUrl, saleTime, status: 'watching', timers: [], ownerId: req.user.id };

  scheduleAlerts(id, { eventName, ticketUrl, saleTime });

  await sendTelegram(
    `👀 <b>Monitor started</b>\n\nEvent: <b>${eventName}</b>\n` +
    `Sale: <b>${new Date(saleTime).toLocaleString('en-PH', { timeZone: 'Asia/Manila' })} PHT</b>\n` +
    `Link: <a href="${ticketUrl}">${ticketUrl}</a>\n\nAlerts: 5 min, 1 min, and at sale time.`
  );

  res.json({ id, status: 'watching' });
});

app.post('/api/monitor/stop', requireAuth, (req, res) => {
  const { id } = req.body;
  const m = monitors[id];
  if (!m) return res.status(404).json({ error: 'Not found' });
  if (m.ownerId !== req.user.id && req.user.role !== 'admin')
    return res.status(403).json({ error: 'Forbidden' });
  m.timers.forEach(t => clearTimeout(t));
  m.status = 'stopped';
  res.json({ ok: true });
});

app.get('/api/monitor/:id', requireAuth, (req, res) => {
  const m = monitors[req.params.id];
  if (!m) return res.status(404).json({ error: 'Not found' });
  if (m.ownerId !== req.user.id && req.user.role !== 'admin')
    return res.status(403).json({ error: 'Forbidden' });
  res.json({ id: m.id, status: m.status, eventName: m.eventName, ticketUrl: m.ticketUrl, saleTime: m.saleTime });
});

app.get('/api/monitors', requireAuth, (req, res) => {
  const list = Object.values(monitors)
    .filter(m => req.user.role === 'admin' || m.ownerId === req.user.id)
    .map(({ id, status, eventName, ticketUrl, saleTime, ownerId }) =>
      ({ id, status, eventName, ticketUrl, saleTime, ownerId }));
  res.json(list);
});

// ─── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ ok: true, service: 'TicketSnap' }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`TicketSnap on :${PORT}`));
