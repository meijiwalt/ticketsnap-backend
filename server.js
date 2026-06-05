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
const DEFAULT_INTERVAL = Math.max(15, Number(process.env.DEFAULT_CHECK_INTERVAL_SEC || 30));
// Keep this reasonable so the private checker does not hammer ticketing sites.
const MIN_INTERVAL     = Math.max(5, Number(process.env.MIN_CHECK_INTERVAL_SEC || 15));
const USE_BROWSER_CHECKER = String(process.env.USE_BROWSER_CHECKER || 'true').toLowerCase() !== 'false';
const BROWSER_CHECK_TIMEOUT_MS = Math.max(15000, Number(process.env.BROWSER_CHECK_TIMEOUT_MS || 25000));

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

function decodeEntities(text = '') {
  return String(text)
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&#(\d+);/g, (_, n) => {
      try { return String.fromCharCode(Number(n)); } catch { return ' '; }
    });
}

function normalizeText(html = '') {
  return decodeEntities(String(html))
    // Keep JSON/JS text too because many ticket pages store button labels in embedded scripts.
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(/[^a-z0-9$%&:/.?=_#-]+/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

function keywordRegex(keyword = '') {
  const normalized = normalizeText(keyword);
  if (!normalized) return null;
  const escaped = normalized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // Allow spaces, dashes, underscores, newlines, or HTML tags/entities between words.
  return new RegExp(escaped.replace(/\\ /g, '[\\s\\-_]+'), 'i');
}

function findKeywordHits(searchText, keywords = []) {
  const text = normalizeText(searchText);
  const raw = decodeEntities(String(searchText)).toLowerCase();
  return [...new Set((keywords || [])
    .map(k => String(k || '').trim())
    .filter(Boolean)
    .filter(k => {
      const nk = normalizeText(k);
      const rx = keywordRegex(k);
      return (nk && text.includes(nk)) || (rx && rx.test(raw));
    }))];
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

function getPageTitle(html = '') {
  const text = String(html || '');
  const match = text.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (match && match[1]) {
    return match[1].replace(/\s+/g, ' ').trim().slice(0, 180);
  }
  return text.replace(/\s+/g, ' ').trim().slice(0, 180);
}

function hashContent(input = '') {
  return crypto.createHash('sha256').update(String(input).slice(0, 750000)).digest('hex');
}


function absolutizeUrl(href = '', base = '') {
  try { return new URL(href, base).toString(); } catch { return ''; }
}

function textHasKeyword(text = '', keyword = '') {
  const nk = normalizeText(keyword);
  if (!nk) return false;
  const nt = normalizeText(text);
  const rx = keywordRegex(keyword);
  return nt.includes(nk) || (rx && rx.test(decodeEntities(String(text)).toLowerCase()));
}

function getAttr(attrs = '', name = '') {
  const rxQuoted = new RegExp(`${name}\\s*=\\s*[\"']([^\"']+)[\"']`, 'i');
  const rxBare = new RegExp(`${name}\\s*=\\s*([^\\s>]+)`, 'i');
  const m = attrs.match(rxQuoted) || attrs.match(rxBare);
  return m ? decodeEntities(m[1] || '') : '';
}

function cleanElementText(input = '') {
  return decodeEntities(String(input))
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function extractClickableCandidatesFromHtml(html = '', baseUrl = '') {
  const candidates = [];
  const anchorRx = /<a\b([^>]*)>([\s\S]*?)<\/a>/gi;
  let match;
  while ((match = anchorRx.exec(html)) && candidates.length < 120) {
    const attrs = match[1] || '';
    const inner = match[2] || '';
    // Ticketmaster Philippines often stores the real destination in data-href.
    const rawHref = getAttr(attrs, 'href') || getAttr(attrs, 'data-href') || getAttr(attrs, 'data-url');
    const href = rawHref ? absolutizeUrl(rawHref, baseUrl) : '';
    const text = cleanElementText(inner).slice(0, 180);
    const aria = getAttr(attrs, 'aria-label') || getAttr(attrs, 'title');
    const hay = `${text} ${aria} ${href}`.trim();
    if (hay) candidates.push({ type: 'link', text: text || aria || href, href, actionable: Boolean(href) });
  }
  const buttonRx = /<button\b([^>]*)>([\s\S]*?)<\/button>/gi;
  while ((match = buttonRx.exec(html)) && candidates.length < 180) {
    const attrs = match[1] || '';
    const text = cleanElementText(match[2] || '').slice(0, 180);
    const aria = getAttr(attrs, 'aria-label') || getAttr(attrs, 'title');
    const rawHref = getAttr(attrs, 'href') || getAttr(attrs, 'data-href') || getAttr(attrs, 'data-url');
    const href = rawHref ? absolutizeUrl(rawHref, baseUrl) : '';
    if (text || aria || href) candidates.push({ type: 'button', text: text || aria || href, href, actionable: Boolean(href) });
  }
  return candidates;
}

function findMatchedActions(candidates = [], positiveKeywords = [], negativeKeywords = [], baseUrl = '') {
  const out = [];
  const seen = new Set();
  for (const c of candidates) {
    const hay = `${c.text || ''} ${c.href || ''}`;
    const matchedPositive = (positiveKeywords || []).filter(k => textHasKeyword(hay, k));
    if (!matchedPositive.length) continue;
    const matchedNegative = (negativeKeywords || []).filter(k => textHasKeyword(hay, k));
    if (matchedNegative.length) continue;
    const href = c.href ? absolutizeUrl(c.href, baseUrl) : '';
    const key = `${c.type}|${href}|${c.text}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      type: c.type || 'element',
      text: String(c.text || '').slice(0, 180),
      href,
      matchedKeywords: matchedPositive.slice(0, 6),
      manualOnly: true,
      note: href ? 'Open this matched official link manually.' : 'Matched a page control. Open the ticketing page and click it manually; TicketSnap will not remote-click ticketing controls.'
    });
    if (out.length >= 10) break;
  }
  return out;
}

async function fetchPageSnapshot(url) {
  if (!USE_BROWSER_CHECKER) {
    const r = await axios.get(url, {
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
    return { html, text: normalizeText(html), status: r.status, engine: 'http', candidates: extractClickableCandidatesFromHtml(html, url), finalUrl: url };
  }

  try {
    const { chromium } = require('playwright');
    const browser = await chromium.launch({ args: ['--no-sandbox', '--disable-setuid-sandbox'] });
    const page = await browser.newPage({
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125 Safari/537.36',
      viewport: { width: 1365, height: 900 }
    });
    const resp = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: BROWSER_CHECK_TIMEOUT_MS });
    try { await page.waitForLoadState('networkidle', { timeout: 6000 }); } catch {}
    await page.waitForTimeout(1500);
    const snapshot = await page.evaluate(() => {
      const candidates = Array.from(document.querySelectorAll('a,button,[role="button"]')).slice(0, 220).map(el => {
        const rawHref = el.getAttribute('data-href') || el.getAttribute('href') || el.getAttribute('data-url') || el.href || '';
        const text = (el.innerText || el.textContent || el.getAttribute('aria-label') || el.getAttribute('title') || '').replace(/\s+/g, ' ').trim().slice(0, 180);
        return {
          type: el.tagName.toLowerCase() === 'a' ? 'link' : 'button',
          text: text || rawHref,
          href: rawHref,
          actionable: Boolean(rawHref)
        };
      }).filter(x => x.text || x.href);
      return {
        html: document.documentElement.outerHTML || '',
        text: document.body ? (document.body.innerText || document.body.textContent || '') : '',
        candidates,
        title: document.title || '',
        finalUrl: location.href
      };
    });
    const status = resp ? resp.status() : 0;
    await browser.close();
    return { html: `${snapshot.title}\n${snapshot.text}\n${snapshot.html}`, text: snapshot.text, status, engine: 'browser', candidates: snapshot.candidates, finalUrl: snapshot.finalUrl || url };
  } catch (browserError) {
    console.warn('[Checker] Browser check failed, falling back to HTTP:', browserError.message);
    const r = await axios.get(url, { timeout: 12000, maxRedirects: 5, validateStatus: s => s >= 200 && s < 500 });
    const html = typeof r.data === 'string' ? r.data : JSON.stringify(r.data);
    return { html, text: normalizeText(html), status: r.status, engine: `http-fallback: ${browserError.message}`, candidates: extractClickableCandidatesFromHtml(html, url), finalUrl: url };
  }
}

function addActivity(m, type, message) {
  m.activity = Array.isArray(m.activity) ? m.activity.slice(-29) : [];
  m.activity.push({ at: new Date().toISOString(), type, message });
}

function summarizePage(html = '', positiveKeywords = DEFAULT_POSITIVE_KEYWORDS, negativeKeywords = DEFAULT_NEGATIVE_KEYWORDS) {
  const text = normalizeText(html);
  const snippets = [];
  const watchTerms = [...positiveKeywords, ...negativeKeywords, ...DEFAULT_POSITIVE_KEYWORDS, ...DEFAULT_NEGATIVE_KEYWORDS, 'presale', 'onsale', 'sold out', 'unavailable'];
  for (const term of watchTerms) {
    const needle = normalizeText(term);
    if (!needle) continue;
    const idx = text.indexOf(needle);
    if (idx >= 0) snippets.push(text.slice(Math.max(0, idx - 90), idx + needle.length + 120));
    if (snippets.length >= 8) break;
  }
  return [...new Set(snippets)];
}

function isBlockedStatus(status) {
  return [401, 403, 407, 429, 451].includes(Number(status));
}

function analyzeAvailability(html, positiveKeywords = DEFAULT_POSITIVE_KEYWORDS, negativeKeywords = DEFAULT_NEGATIVE_KEYWORDS, httpStatus = 0, engine = '') {
  const positiveHits = findKeywordHits(html, positiveKeywords);
  const negativeHits = findKeywordHits(html, negativeKeywords);
  const positiveHit = positiveHits[0];
  const negativeHit = negativeHits[0];
  if (isBlockedStatus(httpStatus)) {
    return {
      available: false,
      blocked: true,
      reason: `Checker blocked by website / HTTP ${httpStatus}. TicketSnap could not read the real event page, so keyword results are not reliable. Use the Pre-open ticketing page button and check manually.`,
      positiveHits,
      negativeHits
    };
  }
  if (positiveHit && !negativeHit) return { available: true, blocked: false, reason: `Matched keyword: ${positiveHit}`, positiveHits, negativeHits };
  if (positiveHit && negativeHit) return { available: false, blocked: false, reason: `Mixed signal: matched ${positiveHit}; also found negative keyword ${negativeHit}`, positiveHits, negativeHits };
  if (negativeHit) return { available: false, blocked: false, reason: `Not available signal: ${negativeHit}`, positiveHits, negativeHits };
  return { available: false, blocked: false, reason: 'No availability keyword found in successfully loaded page HTML', positiveHits, negativeHits };
}

async function checkAvailability(id, manual = false) {
  const m = monitors[id];
  if (!m || m.status === 'stopped') return null;
  try {
    const snapshot = await fetchPageSnapshot(m.ticketUrl);
    const html = snapshot.html || snapshot.text || '';
    const result = analyzeAvailability(html, m.positiveKeywords, m.negativeKeywords, snapshot.status, snapshot.engine);
    const matchedActions = findMatchedActions(snapshot.candidates || [], m.positiveKeywords, m.negativeKeywords, snapshot.finalUrl || m.ticketUrl);
    const digest = hashContent(html);
    const pageChanged = Boolean(m.lastContentHash && m.lastContentHash !== digest);
    const nowIso = new Date().toISOString();
    m.lastCheckedAt = nowIso;
    m.lastHttpStatus = snapshot.status;
    m.lastCheckReason = result.reason;
    m.lastBlocked = Boolean(result.blocked);
    m.lastContentHash = digest;
    m.lastSignals = summarizePage(html, m.positiveKeywords, m.negativeKeywords);
    m.lastPositiveHits = result.positiveHits || [];
    m.lastNegativeHits = result.negativeHits || [];
    m.lastMatchedActions = matchedActions;
    m.lastDiagnostics = {
      title: getPageTitle(html),
      finalUrl: snapshot.finalUrl || m.ticketUrl,
      candidateCount: Array.isArray(snapshot.candidates) ? snapshot.candidates.length : 0,
      blocked: result.blocked,
      status: snapshot.status,
      engine: snapshot.engine
    };
    const preferredAction = matchedActions.find(a => a && a.href && /^https?:\/\//i.test(String(a.href)));
    m.preferredManualUrl = preferredAction ? preferredAction.href : null;
    m.preferredManualLabel = preferredAction ? `Matched link: ${(preferredAction.matchedKeywords || []).join(', ') || preferredAction.text || 'keyword'}` : null;
    m.lastCheckEngine = snapshot.engine;
    m.finalUrl = snapshot.finalUrl || m.ticketUrl;
    m.pageChangeCount = (m.pageChangeCount || 0) + (pageChanged ? 1 : 0);
    m.checkCount = (m.checkCount || 0) + 1;
    m.error = null;

    if (manual) addActivity(m, result.blocked ? 'blocked' : 'manual-check', `Manual check completed: ${result.reason}`);
    if (pageChanged) {
      m.lastChangedAt = nowIso;
      addActivity(m, 'page-change', 'Ticketing event page content changed. Review the event page manually.');
      if (m.alertOnPageChange !== false) {
        await sendTelegram(`🔎 <b>TicketSnap page change detected</b>\n\n<b>${m.eventName}</b>\nReason: ${result.reason}\n\n👉 <a href="${m.ticketUrl}">Open ticketing page</a>`);
      }
    }

    if (result.blocked) {
      m.status = 'blocked';
      m.availableAt = null;
    }

    if (result.available && m.status !== 'available') {
      m.status = 'available';
      m.availableAt = nowIso;
      addActivity(m, 'availability', result.reason);
      await sendTelegram(`🎟 <b>POSSIBLE TICKET AVAILABILITY DETECTED</b>\n\n<b>${m.eventName}</b>\n${result.reason}\n\n👉 <a href="${m.preferredManualUrl || m.ticketUrl}">${m.preferredManualUrl ? 'Open matched ticket link manually' : 'Open ticketing page now'}</a>`);
    } else if (!result.available && m.status !== 'stopped') {
      // Important: sale time alone is NOT availability.
      // Keep monitoring until the ticketing page check finds real positive availability signals.
      m.status = 'checking';
      m.availableAt = null;
    }
    saveData();
    return { ...result, httpStatus: snapshot.status, engine: snapshot.engine, manual, pageChanged, signals: m.lastSignals, positiveHits: m.lastPositiveHits, negativeHits: m.lastNegativeHits, matchedActions: m.lastMatchedActions, preferredManualUrl: m.preferredManualUrl, preferredManualLabel: m.preferredManualLabel }; 
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
  add(15 * 60 * 1000, () => sendTelegram(`🕒 <b>15 minutes to go</b>\n\n<b>${m.eventName}</b> tickets may open soon. Open your browser and be ready.\n\n👉 <a href="${m.ticketUrl}">Ticketing event page</a>`));
  add(5 * 60 * 1000, () => sendTelegram(`⏰ <b>5 minutes to go!</b>\n\n<b>${m.eventName}</b> tickets may open in 5 minutes.\n\n👉 <a href="${m.ticketUrl}">Get ready</a>`));
  add(1 * 60 * 1000, () => sendTelegram(`🔔 <b>1 minute!</b>\n\n<b>${m.eventName}</b> — be ready on your screen.\n\n👉 <a href="${m.ticketUrl}">Stand by</a>`));
  add(0, async () => {
    if (monitors[id] && monitors[id].status !== 'available' && monitors[id].status !== 'stopped') {
      // Sale time reached is only a reminder, not proof that tickets are available.
      monitors[id].status = 'checking';
      monitors[id].saleTimeReached = true;
    }
    saveData();
    await sendTelegram(`🎟 <b>SALE TIME REACHED</b>\n\n<b>${m.eventName}</b>\nThis is only the scheduled sale time. TicketSnap will still wait for page signals before marking tickets as available.\n\n👉 <a href="${m.ticketUrl}">Open ticketing page</a>`);
    checkAvailability(id, true);
  });
  if (saleMs <= now && m.status !== 'available' && m.status !== 'stopped') {
    m.status = 'checking';
    m.saleTimeReached = true;
  }
}

async function startAvailabilityChecker(id) {
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
    const adaptive = minutesToSale <= 2 ? Math.min(configured, 5) : minutesToSale <= 10 ? Math.min(configured, 10) : minutesToSale <= 30 ? Math.min(configured, 15) : minutesToSale <= 60 ? Math.min(configured, 20) : Math.min(configured, 30);
    clearInterval(fresh.checker);
    fresh.checker = setInterval(tick, adaptive * 1000);
  };
  // Run the first check immediately so the Watch tab does not wait for the first interval.
  await checkAvailability(id, true);
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
  await startAvailabilityChecker(id);
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


app.delete('/api/monitor/:id', requireAuth, (req, res) => {
  const m = monitors[req.params.id];
  if (!m) return res.status(404).json({ error: 'Not found' });
  if (m.ownerId !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  m.timers?.forEach(t => clearTimeout(t));
  if (m.checker) clearInterval(m.checker);
  delete monitors[req.params.id];
  if (req.params.id === req.body?.activeMonitorId) {
    // no-op helper for older clients
  }
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
    const pos = Array.isArray(positiveKeywords) && positiveKeywords.length ? positiveKeywords : DEFAULT_POSITIVE_KEYWORDS;
    const neg = Array.isArray(negativeKeywords) && negativeKeywords.length ? negativeKeywords : DEFAULT_NEGATIVE_KEYWORDS;
    const snapshot = await fetchPageSnapshot(ticketUrl);
    const html = snapshot.html || snapshot.text || '';
    const result = analyzeAvailability(html, pos, neg, snapshot.status, snapshot.engine);
    const matchedActions = findMatchedActions(snapshot.candidates || [], pos, neg, snapshot.finalUrl || ticketUrl);
    const preferredAction = matchedActions.find(a => a && a.href && /^https?:\/\//i.test(String(a.href)));
    res.json({ ok: true, httpStatus: snapshot.status, engine: snapshot.engine, result, signals: summarizePage(html, pos, neg), matchedActions, preferredManualUrl: preferredAction ? preferredAction.href : null, diagnostics: { title: getPageTitle(html), finalUrl: snapshot.finalUrl || ticketUrl, candidateCount: Array.isArray(snapshot.candidates) ? snapshot.candidates.length : 0, blocked: result.blocked, status: snapshot.status } });
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

app.get('/', (req, res) => res.json({ ok: true, service: 'TicketSnap', availabilityChecker: true, browserChecker: USE_BROWSER_CHECKER, safeMode: true }));

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
