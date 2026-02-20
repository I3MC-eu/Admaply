const http = require('http');
const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const STORE_FILE = path.join(DATA_DIR, 'store.json');
const sessions = new Map();

const DEFAULT_STORE = {
  users: [{ username: 'demo', email: 'demo@admaply.local', password: 'demo123' }],
  routes: {}
};

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml'
};

async function ensureStore() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(STORE_FILE);
  } catch {
    await fs.writeFile(STORE_FILE, JSON.stringify(DEFAULT_STORE, null, 2));
  }
}

async function readStore() {
  await ensureStore();
  return JSON.parse(await fs.readFile(STORE_FILE, 'utf8'));
}

async function writeStore(store) {
  await fs.writeFile(STORE_FILE, JSON.stringify(store, null, 2));
}

function sendJson(res, code, payload, headers = {}) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(JSON.stringify(payload));
}

function parseCookies(req) {
  const raw = req.headers.cookie || '';
  return raw.split(';').reduce((acc, entry) => {
    const [key, value] = entry.trim().split('=');
    if (key && value) acc[key] = decodeURIComponent(value);
    return acc;
  }, {});
}

function createSession(user) {
  const sid = crypto.randomBytes(24).toString('hex');
  const key = String((user.email || user.username || '').trim().toLowerCase());
  const username = String(user.username || user.email || '').trim();
  const email = String(user.email || '').trim().toLowerCase();

  sessions.set(sid, {
    key,
    username,
    email
  });

  return sid;
}

function getSessionUser(req) {
  const sid = parseCookies(req).sid;
  return sid ? sessions.get(sid) || null : null;
}

async function readJsonBody(req) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
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

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());
}

function normalizeWaypoint(waypoint, index) {
  const rawLinks = Array.isArray(waypoint.links)
    ? waypoint.links
    : (waypoint.url ? [waypoint.url] : []);
  const rawNotes = Array.isArray(waypoint.notes)
    ? waypoint.notes
    : (typeof waypoint.notes === 'string' && waypoint.notes.trim() ? [waypoint.notes] : []);

  return {
    lat: Number(waypoint.lat),
    lng: Number(waypoint.lng),
    name: String(waypoint.name || `Waypoint ${index + 1}`),
    links: rawLinks.map((v) => String(v || '').trim()).filter(Boolean),
    notes: rawNotes.map((v) => String(v || '').trim()).filter(Boolean)
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
    const username = String(body.username || email.split('@')[0] || 'user').trim();

    if (!isValidEmail(email)) return sendJson(res, 400, { error: 'Please provide a valid email address' });
    if (password.length < 6) return sendJson(res, 400, { error: 'Password must be at least 6 characters' });

    const store = await readStore();
    const exists = store.users.some((entry) => String(entry.email || '').toLowerCase() === email);
    if (exists) return sendJson(res, 409, { error: 'Email already registered' });

    const newUser = { username, email, password };
    store.users.push(newUser);
    await writeStore(store);

    const sid = createSession(newUser);
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
    const username = String(body.username || '').trim();
    const password = String(body.password || '');
    if ((!email && !username) || !password) {
      return sendJson(res, 400, { error: 'Email and password are required' });
    }

    const store = await readStore();
    const user = store.users.find((entry) => {
      const entryEmail = String(entry.email || '').toLowerCase();
      const entryUsername = String(entry.username || '');
      const identityMatch = email ? entryEmail === email : entryUsername === username;
      return identityMatch && entry.password === password;
    });

    if (!user) return sendJson(res, 401, { error: 'Invalid credentials' });

    const sid = createSession(user);
    return sendJson(
      res,
      200,
      { ok: true, user: { username: user.username || user.email, email: user.email || '' } },
      { 'Set-Cookie': `sid=${sid}; HttpOnly; Path=/; Max-Age=43200; SameSite=Lax` }
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

    const store = await readStore();
    store.routes[user.key] = store.routes[user.key] || [];
    const userRoutes = store.routes[user.key];

    if (pathname === '/api/routes/latest' && req.method === 'GET') {
      const latest = userRoutes[userRoutes.length - 1] || null;
      if (!latest) return sendJson(res, 200, { route: null });
      return sendJson(res, 200, { route: { ...latest, segmentModes: normalizeSegmentModes(latest.segmentModes, latest.waypoints.length) } });
    }

    if (pathname === '/api/routes' && req.method === 'GET') {
      return sendJson(res, 200, { routes: userRoutes.slice().reverse().map(summarizeRoute) });
    }

    if (pathname === '/api/routes' && req.method === 'POST') {
      const body = await readJsonBody(req);
      if (!body) return sendJson(res, 400, { error: 'Invalid JSON body' });

      const { waypoints, name, segmentModes } = body;
      if (!Array.isArray(waypoints) || waypoints.length < 2) {
        return sendJson(res, 400, { error: 'At least 2 waypoints are required' });
      }

      const cleanWaypoints = waypoints.map(normalizeWaypoint);
      const hasInvalidCoords = cleanWaypoints.some((wp) => Number.isNaN(wp.lat) || Number.isNaN(wp.lng));
      if (hasInvalidCoords) {
        return sendJson(res, 400, { error: 'Waypoints must contain valid lat/lng values' });
      }

      const entry = {
        id: Date.now(),
        name: String(name || '').trim() || `Route ${userRoutes.length + 1}`,
        createdAt: new Date().toISOString(),
        waypoints: cleanWaypoints,
        segmentModes: normalizeSegmentModes(segmentModes, cleanWaypoints.length)
      };

      userRoutes.push(entry);
      await writeStore(store);
      return sendJson(res, 200, { ok: true, route: entry });
    }

    if (pathname.startsWith('/api/routes/') && req.method === 'GET') {
      const routeId = Number(pathname.split('/').pop());
      if (Number.isNaN(routeId)) return sendJson(res, 400, { error: 'Invalid route id' });

      const route = userRoutes.find((entry) => entry.id === routeId) || null;
      if (!route) return sendJson(res, 404, { error: 'Route not found' });
      return sendJson(res, 200, { route: { ...route, segmentModes: normalizeSegmentModes(route.segmentModes, route.waypoints.length) } });
    }
  }

  return serveStatic(pathname, res);
}

const server = http.createServer((req, res) => {
  handler(req, res).catch((error) => {
    console.error(error);
    sendJson(res, 500, { error: 'Internal server error' });
  });
});

ensureStore().then(() => {
  server.listen(PORT, () => {
    console.log(`AdMaply server running on http://localhost:${PORT}`);
  });
});
