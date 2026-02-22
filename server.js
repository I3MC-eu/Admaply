const http = require('http');
const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT) || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DB_FILE = process.env.DB_FILE || path.join(DATA_DIR, 'admaply.db');
const LEGACY_STORE_FILE = path.join(DATA_DIR, 'store.json');
const sessions = new Map();
const loginAttempts = new Map();

const LOGIN_RATE_LIMIT = {
  maxAttempts: 8,
  windowMs: 10 * 60 * 1000
};

const DEFAULT_DEMO_USER = {
  username: 'demo',
  email: 'demo@admaply.local',
  password: 'demo123'
};

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml'
};

const LIMITS = {
  email: 160,
  password: 128,
  username: 60,
  routeName: 80,
  waypointName: 80,
  listItems: 25,
  textItem: 400,
  imageUrl: 800,
  notes: 40,
  waypoints: 100
};

let db;

function logEvent(level, event, details = {}) {
  const entry = {
    ts: new Date().toISOString(),
    level,
    event,
    ...details
  };
  const line = JSON.stringify(entry);
  if (level === 'error') {
    console.error(line);
    return;
  }
  console.log(line);
}

function sanitizeText(value, maxLength) {
  const cleaned = String(value || '')
    .replace(/[\u0000-\u001F\u007F]/g, ' ')
    .replace(/[<>]/g, '')
    .trim();
  return cleaned.slice(0, maxLength);
}

function sanitizeArray(values, maxItems, maxLength) {
  if (!Array.isArray(values)) return [];
  return values
    .slice(0, maxItems)
    .map((value) => sanitizeText(value, maxLength))
    .filter(Boolean);
}

function isValidEmail(email) {
  const candidate = String(email || '').trim().toLowerCase();
  if (!candidate || candidate.length > LIMITS.email) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(candidate);
}

function isValidHttpUrl(url) {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, 64);
  return `scrypt:${salt.toString('hex')}:${derived.toString('hex')}`;
}

function verifyPassword(password, passwordHash) {
  if (!passwordHash || !passwordHash.startsWith('scrypt:')) return false;
  const [, saltHex, hashHex] = passwordHash.split(':');
  if (!saltHex || !hashHex) return false;

  const salt = Buffer.from(saltHex, 'hex');
  const expected = Buffer.from(hashHex, 'hex');
  const actual = crypto.scryptSync(password, salt, expected.length);
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function parseCookies(req) {
  const raw = req.headers.cookie || '';
  return raw.split(';').reduce((acc, entry) => {
    const [key, value] = entry.trim().split('=');
    if (key && value) acc[key] = decodeURIComponent(value);
    return acc;
  }, {});
}

function getClientIp(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded || req.socket.remoteAddress || 'unknown';
}

function getRateLimitState(req, identity) {
  const ip = getClientIp(req);
  const key = `${ip}|${String(identity || '').toLowerCase()}`;
  const now = Date.now();
  const current = loginAttempts.get(key);

  if (!current || now - current.first > LOGIN_RATE_LIMIT.windowMs) {
    const fresh = { count: 0, first: now };
    loginAttempts.set(key, fresh);
    return { key, state: fresh };
  }

  return { key, state: current };
}

function isLoginRateLimited(req, identity) {
  const { state } = getRateLimitState(req, identity);
  return state.count >= LOGIN_RATE_LIMIT.maxAttempts;
}

function recordFailedLogin(req, identity) {
  const { state } = getRateLimitState(req, identity);
  state.count += 1;
}

function clearFailedLogins(req, identity) {
  const { key } = getRateLimitState(req, identity);
  loginAttempts.delete(key);
}

function sendJson(res, code, payload, headers = {}) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(JSON.stringify(payload));
}

async function readJsonBody(req) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 1_000_000) return null;
  }
  if (!body) return {};
  try {
    return JSON.parse(body);
  } catch {
    return null;
  }
}

function isPathSafe(filePath) {
  return path.resolve(filePath).startsWith(path.resolve(ROOT));
}

function isDemoIdentity(user) {
  const email = String((user && user.email) || '').trim().toLowerCase();
  const username = String((user && user.username) || '').trim().toLowerCase();
  return email === DEFAULT_DEMO_USER.email || username === DEFAULT_DEMO_USER.username;
}

function normalizeLinkItems(waypoint) {
  const fromPayload = Array.isArray(waypoint.linkItems) ? waypoint.linkItems : [];
  const normalized = fromPayload
    .slice(0, LIMITS.listItems)
    .map((item) => ({
      url: sanitizeText(item && item.url, LIMITS.imageUrl),
      info: sanitizeText(item && item.info, LIMITS.textItem)
    }))
    .filter((item) => item.url || item.info);

  const legacyLinks = sanitizeArray(waypoint.links, LIMITS.listItems, LIMITS.imageUrl)
    .filter(isValidHttpUrl)
    .map((url) => ({ url, info: '' }));

  return normalized.length > 0 ? normalized : legacyLinks;
}

function normalizeImages(waypoint, linkItems) {
  const images = sanitizeArray(waypoint.images, LIMITS.listItems, LIMITS.imageUrl).filter(isValidHttpUrl);
  if (images.length > 0) return images;

  const legacy = (Array.isArray(waypoint.linkItems) ? waypoint.linkItems : [])
    .map((item) => sanitizeText(item && item.image, LIMITS.imageUrl))
    .filter(isValidHttpUrl);

  return legacy.length > 0 ? legacy : linkItems.map((item) => item.url).filter(isValidHttpUrl);
}

function normalizeWaypoint(waypoint, index) {
  const lat = Number(waypoint.lat);
  const lng = Number(waypoint.lng);
  if (!Number.isFinite(lat) || !Number.isFinite(lng) || lat < -90 || lat > 90 || lng < -180 || lng > 180) {
    return null;
  }

  const linkItems = normalizeLinkItems(waypoint)
    .map((item) => ({
      url: isValidHttpUrl(item.url) ? item.url : '',
      info: sanitizeText(item.info, LIMITS.textItem)
    }))
    .filter((item) => item.url || item.info);

  const notes = sanitizeArray(waypoint.notes, LIMITS.notes, LIMITS.textItem);
  const images = normalizeImages(waypoint, linkItems);

  return {
    lat,
    lng,
    name: sanitizeText(waypoint.name || `Waypoint ${index + 1}`, LIMITS.waypointName) || `Waypoint ${index + 1}`,
    linkItems,
    links: linkItems.map((item) => item.url).filter(Boolean),
    notes,
    images
  };
}

function normalizeSegmentModes(segmentModes, waypointCount) {
  const needed = Math.max(waypointCount - 1, 0);
  const raw = Array.isArray(segmentModes) ? segmentModes : [];
  return Array.from({ length: needed }, (_, index) => (raw[index] === 'hike' ? 'hike' : 'road'));
}

function summarizeRoute(route) {
  return {
    id: route.id,
    name: route.name,
    createdAt: route.createdAt,
    waypointCount: route.waypoints.length,
    waypoints: route.waypoints,
    segmentModes: normalizeSegmentModes(route.segmentModes, route.waypoints.length)
  };
}

function createSession(user) {
  const sid = crypto.randomBytes(24).toString('hex');
  sessions.set(sid, {
    id: user.id,
    username: user.username,
    email: user.email,
    demoRoutes: []
  });
  return sid;
}

function getSessionUser(req) {
  const sid = parseCookies(req).sid;
  return sid ? sessions.get(sid) || null : null;
}

function parseRoutePayload(row) {
  const payload = JSON.parse(row.payload_json);
  return {
    id: row.id,
    name: row.name,
    createdAt: row.created_at,
    waypoints: Array.isArray(payload.waypoints) ? payload.waypoints : [],
    segmentModes: normalizeSegmentModes(payload.segmentModes, (payload.waypoints || []).length)
  };
}

function getDbRoutesForUser(userId) {
  return db
    .prepare('SELECT id, name, created_at, payload_json FROM routes WHERE user_id = ? ORDER BY datetime(created_at) ASC, id ASC')
    .all(userId)
    .map(parseRoutePayload);
}

async function serveStatic(pathname, res) {
  const safePath = path.normalize(decodeURIComponent(pathname === '/' ? '/index.html' : pathname)).replace(/^\/+/, '');
  const filePath = path.join(ROOT, safePath);

  if (!isPathSafe(filePath)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  try {
    const stat = await fs.stat(filePath);
    if (!stat.isFile()) throw new Error('not-file');

    const contentType = MIME_TYPES[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(await fs.readFile(filePath));
  } catch {
    res.writeHead(404);
    res.end('Not found');
  }
}

function ensureSchema() {
  db.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS routes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL COLLATE NOCASE,
      created_at TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(user_id, name)
    );

    CREATE TABLE IF NOT EXISTS route_shares (
      token TEXT PRIMARY KEY,
      route_id INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (route_id) REFERENCES routes(id) ON DELETE CASCADE
    );
  `);
}

function ensureDemoUser() {
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(DEFAULT_DEMO_USER.email);
  if (existing) return;

  db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)').run(
    DEFAULT_DEMO_USER.username,
    DEFAULT_DEMO_USER.email,
    hashPassword(DEFAULT_DEMO_USER.password)
  );
}

async function migrateLegacyStoreIfNeeded() {
  const userCount = db.prepare('SELECT COUNT(*) AS count FROM users').get().count;
  if (userCount > 1) return;

  try {
    const raw = await fs.readFile(LEGACY_STORE_FILE, 'utf8');
    const legacy = JSON.parse(raw);
    if (!Array.isArray(legacy.users)) return;

    const insertUser = db.prepare('INSERT OR IGNORE INTO users (username, email, password_hash) VALUES (?, ?, ?)');
    const findUser = db.prepare('SELECT id, username, email FROM users WHERE email = ? OR username = ? LIMIT 1');
    const insertRoute = db.prepare('INSERT OR IGNORE INTO routes (user_id, name, created_at, payload_json) VALUES (?, ?, ?, ?)');

    for (const user of legacy.users) {
      const username = sanitizeText(user.username || user.email || 'user', LIMITS.username) || 'user';
      const email = String(user.email || '').trim().toLowerCase();
      if (!isValidEmail(email)) continue;

      const passwordHash = user.passwordHash || (user.password ? hashPassword(user.password) : hashPassword(crypto.randomBytes(12).toString('hex')));
      insertUser.run(username, email, passwordHash);

      const persisted = findUser.get(email, username);
      if (!persisted || !legacy.routes) continue;

      const routeKeys = [email, username].map((value) => String(value || '').toLowerCase());
      const legacyRoutes = routeKeys.flatMap((key) => (Array.isArray(legacy.routes[key]) ? legacy.routes[key] : []));

      for (const route of legacyRoutes) {
        if (!route || !Array.isArray(route.waypoints)) continue;
        const waypoints = route.waypoints.map(normalizeWaypoint).filter(Boolean);
        if (waypoints.length < 2) continue;

        const name = sanitizeText(route.name || `Route ${route.id || Date.now()}`, LIMITS.routeName) || `Route ${Date.now()}`;
        const payload = JSON.stringify({
          waypoints,
          segmentModes: normalizeSegmentModes(route.segmentModes, waypoints.length)
        });
        insertRoute.run(persisted.id, name, route.createdAt || new Date().toISOString(), payload);
      }
    }
  } catch {
    // ignore missing or invalid legacy json file
  }
}

async function initDatabase() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  db = new DatabaseSync(DB_FILE);
  ensureSchema();
  ensureDemoUser();
  await migrateLegacyStoreIfNeeded();
}

async function handler(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const { pathname } = url;

  if (pathname === '/api/session' && req.method === 'GET') {
    const user = getSessionUser(req);
    return sendJson(res, 200, user ? { loggedIn: true, user } : { loggedIn: false });
  }

  if (pathname === '/api/signup' && req.method === 'POST') {
    const body = await readJsonBody(req);
    if (!body) return sendJson(res, 400, { error: 'Invalid JSON body' });

    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const username = sanitizeText(body.username || email.split('@')[0] || 'user', LIMITS.username) || 'user';

    if (!isValidEmail(email)) return sendJson(res, 400, { error: 'Please provide a valid email address' });
    if (password.length < 8 || password.length > LIMITS.password) {
      return sendJson(res, 400, { error: 'Password must be between 8 and 128 characters' });
    }

    const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (exists) return sendJson(res, 409, { error: 'Email already registered' });

    const result = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)').run(
      username,
      email,
      hashPassword(password)
    );

    const newUser = { id: Number(result.lastInsertRowid), username, email };
    const sid = createSession(newUser);
    logEvent('info', 'signup_success', { userId: newUser.id, email: newUser.email, ip: getClientIp(req) });

    return sendJson(
      res,
      200,
      { ok: true, user: { username: newUser.username, email: newUser.email } },
      { 'Set-Cookie': `sid=${sid}; HttpOnly; Path=/; Max-Age=43200; SameSite=Lax` }
    );
  }

  if (pathname === '/api/login' && req.method === 'POST') {
    const body = await readJsonBody(req);
    if (!body) return sendJson(res, 400, { error: 'Invalid JSON body' });

    const email = String(body.email || '').trim().toLowerCase();
    const username = sanitizeText(body.username, LIMITS.username);
    const password = String(body.password || '');
    if ((!email && !username) || !password) {
      return sendJson(res, 400, { error: 'Email and password are required' });
    }

    const identity = email || username;
    if (isLoginRateLimited(req, identity)) {
      logEvent('warn', 'login_rate_limited', { identity, ip: getClientIp(req) });
      return sendJson(res, 429, { error: 'Too many login attempts. Please try again later.' });
    }

    const user = email
      ? db.prepare('SELECT id, username, email, password_hash FROM users WHERE email = ? LIMIT 1').get(email)
      : db.prepare('SELECT id, username, email, password_hash FROM users WHERE username = ? LIMIT 1').get(username);

    if (!user || !verifyPassword(password, user.password_hash)) {
      recordFailedLogin(req, identity);
      logEvent('warn', 'login_failed', { identity, ip: getClientIp(req) });
      return sendJson(res, 401, { error: 'Invalid credentials' });
    }

    clearFailedLogins(req, identity);
    logEvent('info', 'login_success', { userId: user.id, email: user.email, ip: getClientIp(req) });

    const sid = createSession(user);
    const cookie = isDemoIdentity(user)
      ? `sid=${sid}; HttpOnly; Path=/; SameSite=Lax`
      : `sid=${sid}; HttpOnly; Path=/; Max-Age=43200; SameSite=Lax`;

    return sendJson(
      res,
      200,
      { ok: true, user: { username: user.username || user.email, email: user.email || '' } },
      { 'Set-Cookie': cookie }
    );
  }

  if (pathname === '/api/logout' && req.method === 'POST') {
    const sid = parseCookies(req).sid;
    if (sid) sessions.delete(sid);
    return sendJson(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; Path=/; Max-Age=0' });
  }

  if (pathname.startsWith('/api/routes')) {
    const user = getSessionUser(req);
    if (!user) return sendJson(res, 401, { error: 'Unauthorized' });

    const isDemoUser = isDemoIdentity(user);
    const userRoutes = isDemoUser ? user.demoRoutes : getDbRoutesForUser(user.id);

    if (pathname === '/api/routes/latest' && req.method === 'GET') {
      const latest = userRoutes[userRoutes.length - 1] || null;
      return sendJson(res, 200, { route: latest });
    }

    if (pathname === '/api/routes' && req.method === 'GET') {
      return sendJson(res, 200, { routes: userRoutes.slice().reverse().map(summarizeRoute) });
    }

    if (pathname === '/api/routes' && req.method === 'POST') {
      const body = await readJsonBody(req);
      if (!body) return sendJson(res, 400, { error: 'Invalid JSON body' });

      const waypoints = Array.isArray(body.waypoints) ? body.waypoints : [];
      if (waypoints.length < 2 || waypoints.length > LIMITS.waypoints) {
        return sendJson(res, 400, { error: 'Waypoints must contain between 2 and 100 points' });
      }

      const cleanWaypoints = waypoints.map(normalizeWaypoint);
      if (cleanWaypoints.some((item) => item === null)) {
        return sendJson(res, 400, { error: 'Waypoints must contain valid lat/lng values' });
      }

      const routeName = sanitizeText(body.name || `Route ${userRoutes.length + 1}`, LIMITS.routeName);
      if (!routeName) return sendJson(res, 400, { error: 'Route name is required' });

      if (isDemoUser) {
        const duplicate = userRoutes.some((route) => route.name.toLowerCase() === routeName.toLowerCase());
        if (duplicate) return sendJson(res, 409, { error: 'A route with this name already exists. Please choose a different name.' });

        const entry = {
          id: Date.now(),
          name: routeName,
          createdAt: new Date().toISOString(),
          waypoints: cleanWaypoints,
          segmentModes: normalizeSegmentModes(body.segmentModes, cleanWaypoints.length)
        };
        userRoutes.push(entry);
        logEvent('info', 'route_created', { userId: user.id || 'demo', routeId: entry.id, routeName, ip: getClientIp(req) });
        return sendJson(res, 200, { ok: true, route: entry });
      }

      try {
        const result = db.prepare('INSERT INTO routes (user_id, name, created_at, payload_json) VALUES (?, ?, ?, ?)').run(
          user.id,
          routeName,
          new Date().toISOString(),
          JSON.stringify({
            waypoints: cleanWaypoints,
            segmentModes: normalizeSegmentModes(body.segmentModes, cleanWaypoints.length)
          })
        );

        const saved = db.prepare('SELECT id, name, created_at, payload_json FROM routes WHERE id = ?').get(Number(result.lastInsertRowid));
        logEvent('info', 'route_created', { userId: user.id, routeId: Number(result.lastInsertRowid), routeName, ip: getClientIp(req) });
        return sendJson(res, 200, { ok: true, route: parseRoutePayload(saved) });
      } catch (error) {
        if (String(error.message || '').includes('UNIQUE constraint failed: routes.user_id, routes.name')) {
          return sendJson(res, 409, { error: 'A route with this name already exists. Please choose a different name.' });
        }
        throw error;
      }
    }

    if (pathname.startsWith('/api/routes/') && req.method === 'GET') {
      const routeId = Number(pathname.split('/').pop());
      if (!Number.isInteger(routeId)) return sendJson(res, 400, { error: 'Invalid route id' });

      if (isDemoUser) {
        const route = userRoutes.find((entry) => entry.id === routeId) || null;
        if (!route) return sendJson(res, 404, { error: 'Route not found' });
        return sendJson(res, 200, { route });
      }

      const row = db
        .prepare('SELECT id, name, created_at, payload_json FROM routes WHERE id = ? AND user_id = ? LIMIT 1')
        .get(routeId, user.id);

      if (!row) return sendJson(res, 404, { error: 'Route not found' });
      return sendJson(res, 200, { route: parseRoutePayload(row) });
    }

    if (pathname.startsWith('/api/routes/') && req.method === 'DELETE') {
      const routeId = Number(pathname.split('/').pop());
      if (!Number.isInteger(routeId)) return sendJson(res, 400, { error: 'Invalid route id' });

      if (isDemoUser) {
        const before = userRoutes.length;
        const kept = userRoutes.filter((entry) => entry.id !== routeId);
        user.demoRoutes = kept;
        if (before === kept.length) return sendJson(res, 404, { error: 'Route not found' });
        logEvent('info', 'route_deleted', { userId: user.id || 'demo', routeId, ip: getClientIp(req) });
        return sendJson(res, 200, { ok: true });
      }

      const result = db.prepare('DELETE FROM routes WHERE id = ? AND user_id = ?').run(routeId, user.id);
      if (result.changes < 1) return sendJson(res, 404, { error: 'Route not found' });
      logEvent('info', 'route_deleted', { userId: user.id, routeId, ip: getClientIp(req) });
      return sendJson(res, 200, { ok: true });
    }

    if (pathname.match(/^\/api\/routes\/\d+\/share$/) && req.method === 'POST') {
      const routeId = Number(pathname.split('/')[3]);
      if (!Number.isInteger(routeId)) return sendJson(res, 400, { error: 'Invalid route id' });

      if (isDemoUser) {
        const route = userRoutes.find((entry) => entry.id === routeId);
        if (!route) return sendJson(res, 404, { error: 'Route not found' });
        return sendJson(res, 400, { error: 'Demo routes cannot be shared publicly' });
      }

      const row = db.prepare('SELECT id FROM routes WHERE id = ? AND user_id = ? LIMIT 1').get(routeId, user.id);
      if (!row) return sendJson(res, 404, { error: 'Route not found' });

      const existing = db.prepare('SELECT token FROM route_shares WHERE route_id = ? LIMIT 1').get(routeId);
      const token = existing ? existing.token : crypto.randomBytes(18).toString('hex');
      if (!existing) {
        db.prepare('INSERT INTO route_shares (token, route_id, created_at) VALUES (?, ?, ?)')
          .run(token, routeId, new Date().toISOString());
      }

      const shareUrl = `${url.origin}/public-route.html?token=${encodeURIComponent(token)}`;
      logEvent('info', 'route_shared', { userId: user.id, routeId, ip: getClientIp(req) });
      return sendJson(res, 200, { ok: true, token, shareUrl });
    }
  }

  if (pathname.startsWith('/api/public/routes/') && req.method === 'GET') {
    const token = sanitizeText(pathname.split('/').pop(), 100);
    if (!token) return sendJson(res, 400, { error: 'Invalid share token' });

    const row = db.prepare(`
      SELECT r.id, r.name, r.created_at, r.payload_json
      FROM route_shares s
      JOIN routes r ON r.id = s.route_id
      WHERE s.token = ?
      LIMIT 1
    `).get(token);

    if (!row) return sendJson(res, 404, { error: 'Shared route not found' });
    return sendJson(res, 200, { route: summarizeRoute(parseRoutePayload(row)) });
  }

  if (pathname === '/api/account' && req.method === 'DELETE') {
    const user = getSessionUser(req);
    if (!user) return sendJson(res, 401, { error: 'Unauthorized' });

    const sid = parseCookies(req).sid;
    if (sid) sessions.delete(sid);

    if (isDemoIdentity(user)) {
      logEvent('info', 'demo_account_session_deleted', { ip: getClientIp(req) });
      return sendJson(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; Path=/; Max-Age=0' });
    }

    db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
    logEvent('info', 'account_deleted', { userId: user.id, email: user.email, ip: getClientIp(req) });
    return sendJson(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; Path=/; Max-Age=0' });
  }

  if (pathname === '/api/account/password' && req.method === 'POST') {
    const user = getSessionUser(req);
    if (!user) return sendJson(res, 401, { error: 'Unauthorized' });
    if (isDemoIdentity(user)) return sendJson(res, 400, { error: 'Demo account password cannot be changed' });

    const body = await readJsonBody(req);
    if (!body) return sendJson(res, 400, { error: 'Invalid JSON body' });

    const currentPassword = String(body.currentPassword || '');
    const newPassword = String(body.newPassword || '');
    if (!currentPassword || !newPassword) {
      return sendJson(res, 400, { error: 'Current and new passwords are required' });
    }
    if (newPassword.length < 8 || newPassword.length > LIMITS.password) {
      return sendJson(res, 400, { error: 'New password must be between 8 and 128 characters' });
    }

    const existing = db.prepare('SELECT id, password_hash FROM users WHERE id = ? LIMIT 1').get(user.id);
    if (!existing) return sendJson(res, 404, { error: 'Account not found' });
    if (!verifyPassword(currentPassword, existing.password_hash)) {
      logEvent('warn', 'password_change_failed', { userId: user.id, reason: 'invalid_current_password', ip: getClientIp(req) });
      return sendJson(res, 401, { error: 'Current password is incorrect' });
    }

    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), user.id);
    logEvent('info', 'password_changed', { userId: user.id, ip: getClientIp(req) });
    return sendJson(res, 200, { ok: true });
  }

  return serveStatic(pathname, res);
}

const server = http.createServer((req, res) => {
  handler(req, res).catch((error) => {
    logEvent('error', 'server_error', {
      method: req.method,
      path: req.url,
      message: String((error && error.message) || error || 'unknown')
    });
    sendJson(res, 500, { error: 'Internal server error' });
  });
});

initDatabase().then(() => {
  server.listen(PORT, () => {
    console.log(`AdMaply server running on http://localhost:${PORT}`);
    console.log(`SQLite DB: ${DB_FILE}`);
  });
});
