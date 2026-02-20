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
  users: [{ username: 'demo', password: 'demo123' }],
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
  const raw = await fs.readFile(STORE_FILE, 'utf8');
  return JSON.parse(raw);
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

function getSessionUser(req) {
  const cookies = parseCookies(req);
  const sid = cookies.sid;
  if (!sid) return null;
  return sessions.get(sid) || null;
}

function createSession(username) {
  const sid = crypto.randomBytes(24).toString('hex');
  sessions.set(sid, { username });
  return sid;
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
  const resolved = path.resolve(filePath);
  return resolved.startsWith(path.resolve(ROOT));
}

async function serveStatic(req, res) {
  const pathname = req.url === '/' ? '/index.html' : req.url;
  const safePath = path.normalize(decodeURIComponent(pathname)).replace(/^\/+/, '');
  const filePath = path.join(ROOT, safePath);

  if (!isPathSafe(filePath)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  try {
    const stat = await fs.stat(filePath);
    if (!stat.isFile()) throw new Error('not-file');

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    const data = await fs.readFile(filePath);
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end('Not found');
  }
}

async function handler(req, res) {
  if (req.url === '/api/session' && req.method === 'GET') {
    const user = getSessionUser(req);
    if (!user) return sendJson(res, 200, { loggedIn: false });
    return sendJson(res, 200, { loggedIn: true, user });
  }

  if (req.url === '/api/login' && req.method === 'POST') {
    const body = await readJsonBody(req);
    if (!body) return sendJson(res, 400, { error: 'Invalid JSON body' });

    const { username, password } = body;
    if (!username || !password) {
      return sendJson(res, 400, { error: 'Username and password are required' });
    }

    const store = await readStore();
    const user = store.users.find((entry) => entry.username === username && entry.password === password);

    if (!user) {
      return sendJson(res, 401, { error: 'Invalid credentials' });
    }

    const sid = createSession(user.username);
    return sendJson(
      res,
      200,
      { ok: true, user: { username: user.username } },
      { 'Set-Cookie': `sid=${sid}; HttpOnly; Path=/; Max-Age=43200; SameSite=Lax` }
    );
  }

  if (req.url === '/api/logout' && req.method === 'POST') {
    const cookies = parseCookies(req);
    if (cookies.sid) sessions.delete(cookies.sid);
    return sendJson(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; Path=/; Max-Age=0' });
  }

  if (req.url === '/api/routes/latest' && req.method === 'GET') {
    const user = getSessionUser(req);
    if (!user) return sendJson(res, 401, { error: 'Unauthorized' });

    const store = await readStore();
    const userRoutes = store.routes[user.username] || [];
    const latest = userRoutes[userRoutes.length - 1] || null;
    return sendJson(res, 200, { route: latest });
  }

  if (req.url === '/api/routes' && req.method === 'POST') {
    const user = getSessionUser(req);
    if (!user) return sendJson(res, 401, { error: 'Unauthorized' });

    const body = await readJsonBody(req);
    if (!body) return sendJson(res, 400, { error: 'Invalid JSON body' });

    const { waypoints, name } = body;
    if (!Array.isArray(waypoints) || waypoints.length === 0) {
      return sendJson(res, 400, { error: 'Waypoints are required' });
    }

    const cleanWaypoints = waypoints.map((waypoint) => ({
      lat: Number(waypoint.lat),
      lng: Number(waypoint.lng),
      name: String(waypoint.name || ''),
      url: String(waypoint.url || ''),
      notes: String(waypoint.notes || '')
    }));

    const store = await readStore();
    store.routes[user.username] = store.routes[user.username] || [];

    const entry = {
      id: Date.now(),
      name: name || `Route ${store.routes[user.username].length + 1}`,
      createdAt: new Date().toISOString(),
      waypoints: cleanWaypoints
    };

    store.routes[user.username].push(entry);
    await writeStore(store);

    return sendJson(res, 200, { ok: true, route: entry });
  }

  return serveStatic(req, res);
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
