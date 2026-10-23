import express from 'express';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import { spawn } from 'node:child_process';
import multer from 'multer';
import unzipper from 'unzipper';
import archiver from 'archiver';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || '/var/data';
const DEFAULT_MODEL = process.env.GOOGLE_MODEL || 'gemini-3.8-flash';
const DEFAULT_PROMPT = `You are an autonomous software engineering assistant. For coding tasks, inspect the actual workspace with the available tools before making claims. When implementation is requested, read the relevant files, create or modify the real files with file tools, run appropriate checks/tests/build commands with the terminal tool, and fix errors when possible. Use web search and web fetch for current or uncertain technical details. Explain results based on actual tool output, and never claim that a file was changed, a command ran, or a test passed unless the tool output confirms it. Keep changes focused and reversible. For cybersecurity, help only with authorized defensive work on systems the user owns or has permission to assess; do not assist with credential theft, unauthorized access, malware deployment, persistence, evasion, or data exfiltration.`;
const REQUIRED_ENV = ['DATABASE_URL', 'SESSION_SECRET', 'ENCRYPTION_KEY', 'ADMIN_USERNAME', 'ADMIN_PASSWORD'];
for (const name of REQUIRED_ENV) {
  if (!process.env[name]) throw new Error(`Missing required environment variable: ${name}`);
}
if (process.env.SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters.');
if (!/^[a-fA-F0-9]{64}$/.test(process.env.ENCRYPTION_KEY)) {
  throw new Error('ENCRYPTION_KEY must be exactly 64 hexadecimal characters (32 bytes).');
}
if (process.env.ADMIN_PASSWORD.length < 16) throw new Error('ADMIN_PASSWORD must be at least 16 characters.');
if (!/^[a-z0-9_.-]{3,32}$/i.test(process.env.ADMIN_USERNAME) || process.env.ADMIN_USERNAME.length > 32) {
  throw new Error('ADMIN_USERNAME must be 3-32 characters using letters, numbers, dot, underscore or hyphen.');
}

const encryptionKey = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 10 });
const PgStore = connectPgSimple(session);
const app = express();
const instances = new Map();
const jobs = new Map();
const activeJobsByUser = new Map();

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));
app.use(session({
  store: new PgStore({ pool, tableName: 'portal_sessions', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false });
const chatLimiter = rateLimit({ windowMs: 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });
const uploadLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 5, standardHeaders: 'draft-7', legacyHeaders: false });
const projectUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024, files: 1 } });

function ensureCsrfToken(req) {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  return req.session.csrfToken;
}
function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function requireCsrf(req, res, next) {
  if (!constantTimeEqual(req.get('x-csrf-token'), req.session?.csrfToken)) {
    return res.status(403).json({ error: 'انتهت صلاحية حماية الطلب. حدّث الصفحة وحاول مجددًا.' });
  }
  next();
}
async function requireUser(req, res, next) {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'سجّل الدخول أولًا.' });
    const result = await pool.query(
      'SELECT id, username, is_admin, is_active, gemini_key_enc, daily_limit, opencode_session_id FROM portal_users WHERE id = $1',
      [req.session.userId]
    );
    if (!result.rowCount) {
      req.session.destroy(() => {});
      return res.status(401).json({ error: 'الحساب غير موجود.' });
    }
    req.user = result.rows[0];
    next();
  } catch (error) { next(error); }
}
function requireAdmin(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'هذه الصفحة للمدير فقط.' });
  next();
}
function encryptSecret(plainText) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
  return `${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${encrypted.toString('hex')}`;
}
function decryptSecret(value) {
  const parts = String(value || '').split(':');
  if (parts.length !== 3) throw new Error('تعذر فك تشفير مفتاح API المحفوظ. تحقق من ENCRYPTION_KEY.');
  const [ivHex, tagHex, dataHex] = parts;
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]).toString('utf8');
}
async function getSettings() {
  const result = await pool.query("SELECT key, value FROM portal_settings WHERE key = 'system_prompt'");
  const settings = Object.fromEntries(result.rows.map((row) => [row.key, row.value]));
  return { systemPrompt: settings.system_prompt || DEFAULT_PROMPT, modelId: DEFAULT_MODEL };
}
async function getTodayUsage(userId) {
  const result = await pool.query('SELECT requests FROM portal_usage_daily WHERE user_id = $1 AND day = CURRENT_DATE', [userId]);
  return Number(result.rows[0]?.requests || 0);
}
async function adminUsers() {
  const result = await pool.query(`
    SELECT u.id, u.username, u.is_active, u.is_admin, u.daily_limit, (u.gemini_key_enc IS NOT NULL) AS has_api_key,
           u.created_at, COALESCE(d.requests, 0)::int AS today_requests
    FROM portal_users u
    LEFT JOIN portal_usage_daily d ON d.user_id = u.id AND d.day = CURRENT_DATE
    WHERE u.is_admin = false
    ORDER BY u.created_at DESC
  `);
  return result.rows;
}
function safeError(error) {
  const message = String(error?.message || 'حدث خطأ غير معروف.');
  return message.replace(/AIza[0-9A-Za-z_\-]{20,}/g, '[API_KEY_REDACTED]').slice(0, 1200);
}

async function allocatePort() {
  return await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

async function createGoogleCredentialProxy(userId, realKey) {
  const userKey = String(userId);
  const proxyToken = crypto.randomBytes(32).toString('hex');
  const proxyServer = http.createServer((req, res) => {
    // The proxy is usable only during a portal job and only with its ephemeral per-instance token.
    if (!activeJobsByUser.has(userKey)) {
      res.writeHead(429, { 'content-type': 'application/json; charset=utf-8' });
      res.end('{"error":"No active request"}');
      return;
    }
    if (!constantTimeEqual(String(req.headers['x-goog-api-key'] || ''), proxyToken)) {
      res.writeHead(401, { 'content-type': 'application/json; charset=utf-8' });
      res.end('{"error":"Unauthorized"}');
      return;
    }

    let parsed;
    try { parsed = new URL(req.url || '/', 'http://127.0.0.1'); }
    catch {
      res.writeHead(400, { 'content-type': 'application/json; charset=utf-8' });
      res.end('{"error":"Bad request"}');
      return;
    }
    if (!parsed.pathname.startsWith('/v1beta/models/')) {
      res.writeHead(404, { 'content-type': 'application/json; charset=utf-8' });
      res.end('{"error":"Not found"}');
      return;
    }
    // Never forward a user-supplied key in the URL. Credentials are added by this server only.
    parsed.searchParams.delete('key');
    const headers = { ...req.headers, host: 'generativelanguage.googleapis.com', 'x-goog-api-key': realKey };
    for (const name of ['connection', 'keep-alive', 'proxy-connection', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'upgrade', 'authorization']) {
      delete headers[name];
    }
    const upstream = https.request({
      hostname: 'generativelanguage.googleapis.com',
      port: 443,
      method: req.method,
      path: `${parsed.pathname}${parsed.search}`,
      headers,
      servername: 'generativelanguage.googleapis.com'
    }, (upstreamRes) => {
      const responseHeaders = { ...upstreamRes.headers };
      for (const name of ['connection', 'keep-alive', 'proxy-connection', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade']) {
        delete responseHeaders[name];
      }
      res.writeHead(upstreamRes.statusCode || 502, responseHeaders);
      upstreamRes.pipe(res);
    });
    upstream.setTimeout(600000, () => upstream.destroy(new Error('Upstream timeout')));
    upstream.on('error', () => {
      if (!res.headersSent) res.writeHead(502, { 'content-type': 'application/json; charset=utf-8' });
      if (!res.writableEnded) res.end('{"error":"Upstream unavailable"}');
    });
    req.pipe(upstream);
  });

  await new Promise((resolve, reject) => {
    proxyServer.once('error', reject);
    proxyServer.listen(0, '127.0.0.1', resolve);
  });
  const port = proxyServer.address().port;
  return {
    server: proxyServer,
    token: proxyToken,
    baseURL: `http://127.0.0.1:${port}/v1beta`
  };
}
function openCodeHeaders(instance) {
  const auth = Buffer.from(`${instance.username}:${instance.password}`).toString('base64');
  return { Authorization: `Basic ${auth}`, 'Content-Type': 'application/json' };
}
async function openCodeFetch(instance, route, options = {}) {
  const timeoutMs = options.timeoutMs || 600000;
  const { timeoutMs: _ignored, ...fetchOptions } = options;
  const response = await fetch(`${instance.url}${route}`, {
    ...fetchOptions,
    headers: { ...openCodeHeaders(instance), ...(fetchOptions.headers || {}) },
    signal: AbortSignal.timeout(timeoutMs)
  });
  const bodyText = await response.text();
  if (!response.ok) throw new Error(`OpenCode HTTP ${response.status}: ${bodyText.slice(0, 900)}`);
  if (!bodyText) return null;
  try { return JSON.parse(bodyText); } catch { return bodyText; }
}
async function waitForOpenCode(instance, child) {
  let lastError;
  for (let attempt = 0; attempt < 40; attempt += 1) {
    if (child.exitCode !== null) throw new Error('OpenCode process stopped while starting. Check Render logs.');
    try {
      const health = await openCodeFetch(instance, '/global/health', { timeoutMs: 2500 });
      if (health?.healthy) return;
    } catch (error) { lastError = error; }
    await new Promise((resolve) => setTimeout(resolve, 750));
  }
  child.kill('SIGTERM');
  throw new Error(`OpenCode did not become ready. ${safeError(lastError)}`);
}
function workspacePath(userId) {
  return path.join(DATA_DIR, 'tenants', String(userId), 'workspace');
}
function isSecretPath(relativePath) {
  const parts = relativePath.split('/');
  return parts.some((part) => part === '.git' || part === 'node_modules' || part === '.env' || (part.startsWith('.env.') && part !== '.env.example')) || relativePath === 'opencode.json';
}
function normalizeWorkspacePath(requested) {
  const input = String(requested || '').replace(/\\/g, '/');
  const normalized = path.posix.normalize(input);
  const invalid = !input || path.posix.isAbsolute(input) || /^[A-Za-z]:/.test(input) || input.split('/').includes('..') || normalized === '.' || normalized === '..' || normalized.startsWith('../') || normalized.includes('/../') || input.includes('\0');
  if (invalid) throw Object.assign(new Error('مسار الملف غير صالح.'), { statusCode: 400 });
  if (isSecretPath(normalized)) throw Object.assign(new Error('الوصول إلى هذا المسار محظور.'), { statusCode: 400 });
  return normalized;
}
async function listWorkspaceFiles(userId, maxFiles = 500) {
  const root = workspacePath(userId);
  await fs.mkdir(root, { recursive: true });
  const files = [];
  async function visit(directory, relative = '', depth = 0) {
    if (depth > 8 || files.length >= maxFiles) return;
    const entries = await fs.readdir(directory, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (files.length >= maxFiles) break;
      const rel = relative ? `${relative}/${entry.name}` : entry.name;
      if (isSecretPath(rel)) continue;
      const absolute = path.join(directory, entry.name);
      const stat = await fs.lstat(absolute).catch(() => null);
      if (!stat || stat.isSymbolicLink()) continue;
      if (stat.isDirectory()) await visit(absolute, rel, depth + 1);
      else if (stat.isFile()) files.push({ path: rel, size: stat.size, absolute });
    }
  }
  await visit(root);
  return files.sort((a,b)=>a.path.localeCompare(b.path));
}
async function ensureOpenCodeInstance(user, settings) {
  const key = decryptSecret(user.gemini_key_enc);
  const cached = instances.get(String(user.id));
  if (cached && cached.child.exitCode === null && cached.modelId === settings.modelId) return cached;
  if (cached) stopInstance(String(user.id));

  const userRoot = path.join(DATA_DIR, 'tenants', String(user.id));
  const home = path.join(userRoot, 'home');
  const workspace = workspacePath(user.id);
  const xdgConfig = path.join(userRoot, 'xdg-config');
  const xdgData = path.join(userRoot, 'xdg-data');
  const xdgState = path.join(userRoot, 'xdg-state');
  for (const directory of [home, workspace, xdgConfig, xdgData, xdgState]) {
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  }
  const modelId = `google/${settings.modelId}`;
  const credentialProxy = await createGoogleCredentialProxy(user.id, key);
  const configPath = path.join(workspace, 'opencode.json');
  try {
    await fs.writeFile(configPath, JSON.stringify({
      '$schema': 'https://opencode.ai/config.json',
      model: modelId,
      provider: {
        google: {
          options: {
            baseURL: credentialProxy.baseURL,
            apiKey: credentialProxy.token
          },
          models: {
            [settings.modelId]: { name: 'Coding model' }
          }
        }
      },
      permission: {
        bash: 'allow',
        edit: { '*': 'allow', 'opencode.json': 'deny' },
        read: { '*': 'allow', '*.env': 'deny', '*.env.*': 'deny', '*.env.example': 'allow', 'opencode.json': 'deny' },
        glob: 'allow',
        grep: 'allow',
        list: 'allow',
        lsp: 'allow',
        task: 'allow',
        todoread: 'allow',
        todowrite: 'allow',
        skill: 'allow',
        question: 'deny',
        external_directory: 'deny',
        webfetch: 'allow',
        websearch: 'allow',
        codesearch: 'allow',
        doom_loop: 'deny'
      }
    }, null, 2), { mode: 0o600 });
  } catch (error) {
    credentialProxy.server.close();
    throw error;
  }
  const port = await allocatePort();
  const instance = {
    url: `http://127.0.0.1:${port}`,
    username: 'portal',
    password: crypto.randomBytes(32).toString('hex'),
    modelId: settings.modelId,
    child: null,
    workspace,
    proxyServer: credentialProxy.server
  };
  const env = {
    PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin',
    LANG: process.env.LANG || 'C.UTF-8',
    HOME: home,
    XDG_CONFIG_HOME: xdgConfig,
    XDG_DATA_HOME: xdgData,
    XDG_STATE_HOME: xdgState,
    OPENCODE_SERVER_USERNAME: instance.username,
    OPENCODE_SERVER_PASSWORD: instance.password,
    OPENCODE_DISABLE_AUTOUPDATE: 'true',
    OPENCODE_ENABLE_EXA: '1',
    OPENCODE_EXPERIMENTAL_LSP_TOOL: 'true'
  };
  const child = spawn('opencode', ['serve', '--hostname', '127.0.0.1', '--port', String(port)], {
    cwd: workspace,
    env,
    stdio: 'ignore'
  });
  child.on('error', (error) => {
    console.error(`OpenCode process failed to start: ${safeError(error)}`);
    try { instance.proxyServer?.close(); } catch {}
  });
  instance.child = child;
  instances.set(String(user.id), instance);
  child.on('exit', () => {
    try { instance.proxyServer?.close(); } catch {}
    if (instances.get(String(user.id)) === instance) instances.delete(String(user.id));
  });
  await waitForOpenCode(instance, child);
  return instance;
}
function stopInstance(userId) {
  const instance = instances.get(String(userId));
  if (instance?.child && instance.child.exitCode === null) instance.child.kill('SIGTERM');
  try { instance?.proxyServer?.close(); } catch {}
  instances.delete(String(userId));
}
function stopAllInstances() {
  for (const userId of instances.keys()) stopInstance(userId);
}
function saveSession(sessionObject) {
  return new Promise((resolve, reject) => sessionObject.save((error) => error ? reject(error) : resolve()));
}

app.get('/healthz', (_req, res) => res.json({ ok: true, service: 'opencode-portal' }));
app.get('/', (req, res) => {
  const token = ensureCsrfToken(req);
  res.type('html').send((awaitIndex).replaceAll('__CSRF_TOKEN__', token));
});
const awaitIndex = await fs.readFile(path.join(__dirname, 'public', 'index.html'), 'utf8');

app.get('/api/me', async (req, res, next) => {
  try {
    const csrfToken = ensureCsrfToken(req);
    if (!req.session.userId) return res.json({ user: null, csrfToken });
    const result = await pool.query(`
      SELECT id, username, is_admin, is_active, (gemini_key_enc IS NOT NULL) AS has_api_key, daily_limit
      FROM portal_users WHERE id = $1
    `, [req.session.userId]);
    if (!result.rowCount) return res.json({ user: null, csrfToken });
    const user = result.rows[0];
    const todayRequests = await getTodayUsage(user.id);
    const payload = {
      user: {
        id: user.id,
        username: user.username,
        isAdmin: user.is_admin,
        isActive: user.is_active,
        hasApiKey: user.has_api_key,
        dailyLimit: user.daily_limit,
        todayRequests
      },
      csrfToken
    };
    if (user.is_admin) {
      const settings = await getSettings();
      payload.settings = { systemPrompt: settings.systemPrompt };
      payload.users = await adminUsers();
    }
    res.json(payload);
  } catch (error) { next(error); }
});

app.post('/api/register', loginLimiter, requireCsrf, async (req, res, next) => {
  try {
    const username = String(req.body?.username || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!/^[a-z0-9_.-]{3,32}$/.test(username)) return res.status(400).json({ error: 'اسم المستخدم يجب أن يكون 3–32 رمزًا من الأحرف الإنجليزية أو الأرقام أو . _ -.' });
    if (password.length < 10 || password.length > 200) return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 10 أحرف على الأقل.' });
    const passwordHash = await bcrypt.hash(password, 12);
    try {
      await pool.query('INSERT INTO portal_users (username, password_hash, is_active, is_admin, daily_limit) VALUES ($1, $2, false, false, 50)', [username, passwordHash]);
    } catch (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'اسم المستخدم مستخدم من قبل.' });
      throw error;
    }
    res.status(201).json({ ok: true, message: 'تم إنشاء الحساب. يحتاج تفعيلًا يدويًا من المدير قبل الاستخدام.' });
  } catch (error) { next(error); }
});

app.post('/api/login', loginLimiter, requireCsrf, async (req, res, next) => {
  try {
    const username = String(req.body?.username || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const result = await pool.query('SELECT id, password_hash, is_active FROM portal_users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة.' });
    await new Promise((resolve, reject) => req.session.regenerate((error) => error ? reject(error) : resolve()));
    req.session.userId = user.id;
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    await saveSession(req.session);
    res.json({ ok: true, csrfToken: req.session.csrfToken });
  } catch (error) { next(error); }
});

app.post('/api/logout', requireCsrf, (req, res) => {
  const userId = req.session.userId;
  if (userId) stopInstance(String(userId));
  req.session.destroy((error) => {
    if (error) return res.status(500).json({ error: 'تعذر تسجيل الخروج.' });
    res.clearCookie('connect.sid', { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' });
    res.json({ ok: true });
  });
});

app.post('/api/key', requireCsrf, requireUser, (_req, res) => {
  res.status(403).json({ error: 'إعداد الحسابات متاح للإدارة فقط.' });
});

app.post('/api/new-chat', requireCsrf, requireUser, async (req, res, next) => {
  try {
    await pool.query('UPDATE portal_users SET opencode_session_id = NULL WHERE id = $1', [req.user.id]);
    res.json({ ok: true });
  } catch (error) { next(error); }
});

app.get('/api/workspace/files', requireUser, async (req, res, next) => {
  try {
    if (!req.user.is_active) return res.status(403).json({ error: 'حسابك بانتظار تفعيل المدير.' });
    const files = await listWorkspaceFiles(req.user.id);
    res.json({ files: files.map(({ path: filePath, size }) => ({ path: filePath, size })), truncated: files.length >= 500 });
  } catch (error) { next(error); }
});

app.get('/api/workspace/file', requireUser, async (req, res, next) => {
  try {
    if (!req.user.is_active) return res.status(403).json({ error: 'حسابك بانتظار تفعيل المدير.' });
    const relative = normalizeWorkspacePath(req.query.path);
    const root = workspacePath(req.user.id);
    const absolute = path.resolve(root, relative);
    if (!absolute.startsWith(`${path.resolve(root)}${path.sep}`)) return res.status(400).json({ error: 'مسار الملف غير صالح.' });
    const stat = await fs.lstat(absolute);
    if (!stat.isFile() || stat.isSymbolicLink()) return res.status(400).json({ error: 'المسار ليس ملفًا عاديًا.' });
    if (stat.size > 500 * 1024) return res.status(413).json({ error: 'الملف أكبر من حد المعاينة (500 KB). نزّل مساحة العمل لعرضه.' });
    const content = await fs.readFile(absolute, 'utf8');
    res.json({ path: relative, content });
  } catch (error) {
    if (error.code === 'ENOENT') return res.status(404).json({ error: 'الملف غير موجود.' });
    next(error);
  }
});

app.post('/api/workspace/upload', uploadLimiter, requireCsrf, requireUser, projectUpload.single('projectZip'), async (req, res, next) => {
  try {
    if (!req.user.is_active) return res.status(403).json({ error: 'حسابك بانتظار تفعيل المدير.' });
    if (!req.file) return res.status(400).json({ error: 'ارفع ملف ZIP أولًا.' });
    if (!req.file.originalname.toLowerCase().endsWith('.zip')) return res.status(400).json({ error: 'المسموح ملف ZIP فقط.' });
    const directory = await unzipper.Open.buffer(req.file.buffer);
    if (directory.files.length > 500) return res.status(413).json({ error: 'الأرشيف يحتوي على ملفات كثيرة (الحد 500).' });
    const allFileEntries = directory.files.filter((entry) => entry.type === 'File');
    const pathParts = allFileEntries.map((entry) => String(entry.path).replace(/\\/g, '/').split('/').filter(Boolean));
    const firstSegments = new Set(pathParts.map((parts) => parts[0]).filter(Boolean));
    const stripCommonRoot = pathParts.length > 0 && pathParts.every((parts) => parts.length > 1) && firstSegments.size === 1;
    const commonRoot = stripCommonRoot ? `${pathParts[0][0]}/` : '';
    const prepared = [];
    let totalBytes = 0;
    for (const entry of directory.files) {
      if (entry.type === 'Directory') continue;
      if (entry.type !== 'File') return res.status(400).json({ error: 'الأرشيف يحتوي على رابط رمزي أو نوع ملف غير مسموح.' });
      const rawEntryPath = String(entry.path).replace(/\\/g, '/');
      const candidatePath = stripCommonRoot && rawEntryPath.startsWith(commonRoot) ? rawEntryPath.slice(commonRoot.length) : rawEntryPath;
      let relative;
      try { relative = normalizeWorkspacePath(candidatePath); }
      catch (pathError) { return res.status(400).json({ error: safeError(pathError) }); }
      if (relative.split('/').some((part) => part === '.git' || part === 'node_modules' || part === '.env' || (part.startsWith('.env.') && part !== '.env.example')) || relative === 'opencode.json') {
        return res.status(400).json({ error: `الملف ${relative} غير مسموح رفعه.` });
      }
      const chunks = [];
      let entryBytes = 0;
      for await (const chunk of entry.stream()) {
        entryBytes += chunk.length;
        totalBytes += chunk.length;
        if (entryBytes > 10 * 1024 * 1024 || totalBytes > 40 * 1024 * 1024) {
          return res.status(413).json({ error: 'حجم الملفات بعد فك الضغط يتجاوز الحد (40 MB إجمالًا أو 10 MB للملف).' });
        }
        chunks.push(chunk);
      }
      prepared.push({ relative, buffer: Buffer.concat(chunks) });
    }
    if (!prepared.length) return res.status(400).json({ error: 'لم أجد ملفات عادية داخل ZIP.' });
    const root = workspacePath(req.user.id);
    await fs.mkdir(root, { recursive: true });
    // Replace workspace contents while preserving the OpenCode safety configuration.
    for (const entry of await fs.readdir(root, { withFileTypes: true })) {
      if (entry.name === 'opencode.json') continue;
      await fs.rm(path.join(root, entry.name), { recursive: true, force: true });
    }
    for (const item of prepared) {
      const absolute = path.resolve(root, item.relative);
      if (!absolute.startsWith(`${path.resolve(root)}${path.sep}`)) throw new Error('مسار ملف غير آمن داخل ZIP.');
      await fs.mkdir(path.dirname(absolute), { recursive: true });
      await fs.writeFile(absolute, item.buffer, { mode: 0o600 });
    }
    stopInstance(String(req.user.id));
    await pool.query('UPDATE portal_users SET opencode_session_id = NULL WHERE id = $1', [req.user.id]);
    res.json({ ok: true, count: prepared.length, bytes: totalBytes, message: `تم رفع ${prepared.length} ملفًا إلى مساحة العمل.` });
  } catch (error) {
    if (error.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'ملف ZIP أكبر من 10 MB.' });
    next(error);
  }
});

app.get('/api/workspace/download', requireUser, async (req, res, next) => {
  try {
    if (!req.user.is_active) return res.status(403).json({ error: 'حسابك بانتظار تفعيل المدير.' });
    const files = await listWorkspaceFiles(req.user.id);
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="workspace.zip"');
    const archive = archiver('zip', { zlib: { level: 6 } });
    archive.on('error', next);
    archive.pipe(res);
    for (const file of files) archive.file(file.absolute, { name: file.path });
    await archive.finalize();
  } catch (error) { next(error); }
});

app.post('/api/chat', chatLimiter, requireCsrf, requireUser, async (req, res, next) => {
  try {
    const prompt = String(req.body?.prompt || '').trim();
    if (!req.user.is_active) return res.status(403).json({ error: 'حسابك بانتظار تفعيل المدير.' });
    if (!req.user.gemini_key_enc) return res.status(400).json({ error: 'لم يتم تجهيز حسابك للاستخدام بعد. تواصل مع الإدارة.' });
    if (prompt.length < 1 || prompt.length > 20000) return res.status(400).json({ error: 'الرسالة فارغة أو أطول من 20,000 حرف.' });
    if (activeJobsByUser.has(String(req.user.id))) return res.status(429).json({ error: 'هناك طلب قيد التنفيذ لحسابك. انتظر حتى ينتهي.' });

    const usage = await pool.query(`
      INSERT INTO portal_usage_daily (user_id, day, requests) VALUES ($1, CURRENT_DATE, 1)
      ON CONFLICT (user_id, day) DO UPDATE SET requests = portal_usage_daily.requests + 1
      RETURNING requests
    `, [req.user.id]);
    if (Number(usage.rows[0].requests) > Number(req.user.daily_limit)) {
      return res.status(429).json({ error: `وصلت إلى حدك اليومي (${req.user.daily_limit} رسالة).` });
    }

    const jobId = crypto.randomUUID();
    const job = { id: jobId, userId: String(req.user.id), status: 'running', output: '', error: '', createdAt: Date.now() };
    jobs.set(jobId, job);
    activeJobsByUser.set(String(req.user.id), jobId);
    const userSnapshot = { ...req.user };
    res.status(202).json({ ok: true, jobId });

    (async () => {
      try {
        const settings = await getSettings();
        const instance = await ensureOpenCodeInstance(userSnapshot, settings);
        let sessionId = userSnapshot.opencode_session_id;
        if (!sessionId) {
          const created = await openCodeFetch(instance, '/session', {
            method: 'POST', body: JSON.stringify({ title: `Workspace ${userSnapshot.username}` })
          });
          sessionId = created?.id;
          if (!sessionId) throw new Error('OpenCode لم يُرجع معرّف الجلسة.');
          await pool.query('UPDATE portal_users SET opencode_session_id = $1 WHERE id = $2', [sessionId, userSnapshot.id]);
        }
        const enforcedPolicy = '\n\nTool-use requirements: When the request involves coding or project files, use the available workspace tools to inspect the relevant files; when a change is requested, make the actual change using file tools; use bash to run relevant checks/tests where feasible; use websearch/webfetch for current external information when appropriate. Report only actions confirmed by tool results.\n\nSafety policy: Only assist with authorized and defensive cybersecurity work. Do not assist with credential theft, unauthorized access, malware deployment, persistence, evasion, or exfiltration.';
        const response = await openCodeFetch(instance, `/session/${encodeURIComponent(sessionId)}/message`, {
          method: 'POST',
          timeoutMs: 600000,
          body: JSON.stringify({
            system: `${settings.systemPrompt}${enforcedPolicy}`,
            parts: [{ type: 'text', text: prompt }]
          })
        });
        const parts = Array.isArray(response?.parts) ? response.parts : [];
        const textParts = parts.filter((part) => part?.type === 'text' && typeof part.text === 'string').map((part) => part.text);
        job.output = textParts.join('\n\n').trim() || 'اكتمل الطلب لكن لم يرجع OpenCode جزءًا نصيًا. راجع سجلات Render إن تكرر الأمر.';
        job.status = 'done';
      } catch (error) {
        const detail = safeError(error);
        job.error = 'تعذّر إكمال الطلب. حاول مجددًا، وإذا تكررت المشكلة تواصل مع الإدارة.';
        job.status = 'error';
        console.error(`[chat job ${job.id}] ${detail}`);
      } finally {
        activeJobsByUser.delete(String(userSnapshot.id));
      }
    })();
  } catch (error) { next(error); }
});

app.get('/api/jobs/:id', requireUser, (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job || job.userId !== String(req.user.id)) return res.status(404).json({ error: 'الطلب غير موجود أو لا يعود لحسابك.' });
  res.json({ id: job.id, status: job.status, output: job.output, error: job.error });
});

app.post('/api/admin/users/:id/active', requireCsrf, requireUser, requireAdmin, async (req, res, next) => {
  try {
    const active = req.body?.active === true;
    const userId = Number(req.params.id);
    const newKey = String(req.body?.apiKey || '').trim();
    if (!Number.isSafeInteger(userId) || userId < 1) return res.status(400).json({ error: 'معرّف مستخدم غير صالح.' });

    const existing = await pool.query(
      'SELECT gemini_key_enc FROM portal_users WHERE id = $1 AND is_admin = false',
      [userId]
    );
    if (!existing.rowCount) return res.status(404).json({ error: 'المستخدم غير موجود.' });

    let encryptedKey = existing.rows[0].gemini_key_enc;
    if (newKey) {
      if (newKey.length < 20 || newKey.length > 300 || /\s/.test(newKey)) {
        return res.status(400).json({ error: 'رمز الخدمة غير صالح. تحقق من نسخه بالكامل.' });
      }
      encryptedKey = encryptSecret(newKey);
    }
    if (active && !encryptedKey) return res.status(400).json({ error: 'أدخل رمز الخدمة قبل تفعيل هذا الحساب.' });

    const result = await pool.query(
      'UPDATE portal_users SET is_active = $1, gemini_key_enc = $2, opencode_session_id = CASE WHEN $2 IS DISTINCT FROM gemini_key_enc THEN NULL ELSE opencode_session_id END WHERE id = $3 AND is_admin = false RETURNING id',
      [active, encryptedKey, userId]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'المستخدم غير موجود.' });
    stopInstance(String(userId));
    res.json({ ok: true, message: active ? 'تم تجهيز الحساب وتفعيله.' : 'تم تعطيل الحساب.' });
  } catch (error) { next(error); }
});

app.post('/api/admin/users/:id/limit', requireCsrf, requireUser, requireAdmin, async (req, res, next) => {
  try {
    const userId = Number(req.params.id);
    const limit = Number(req.body?.dailyLimit);
    if (!Number.isSafeInteger(userId) || userId < 1 || !Number.isInteger(limit) || limit < 1 || limit > 10000) {
      return res.status(400).json({ error: 'حد الاستخدام يجب أن يكون عددًا بين 1 و10000.' });
    }
    const result = await pool.query('UPDATE portal_users SET daily_limit = $1 WHERE id = $2 AND is_admin = false RETURNING id', [limit, userId]);
    if (!result.rowCount) return res.status(404).json({ error: 'المستخدم غير موجود.' });
    res.json({ ok: true });
  } catch (error) { next(error); }
});

app.post('/api/admin/settings', requireCsrf, requireUser, requireAdmin, async (req, res, next) => {
  try {
    const systemPrompt = String(req.body?.systemPrompt || '').trim();
    if (systemPrompt.length < 20 || systemPrompt.length > 30000) return res.status(400).json({ error: 'التعليمات يجب أن تكون بين 20 و30000 حرف.' });
    await pool.query(`INSERT INTO portal_settings (key, value) VALUES ('system_prompt', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, [systemPrompt]);
    res.json({ ok: true, message: 'تم حفظ التعليمات المشتركة.' });
  } catch (error) { next(error); }
});

app.use((error, _req, res, _next) => {
  console.error(`[server error] ${safeError(error)}`);
  if (res.headersSent) return;
  const statusCode = error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE' ? 413 : (Number.isInteger(error.statusCode) && error.statusCode >= 400 && error.statusCode < 500 ? error.statusCode : 500);
  if (statusCode !== 500) return res.status(statusCode).json({ error: safeError(error) });
  res.status(500).json({ error: 'حدث خطأ داخلي. حاول مجددًا، وإذا تكررت المشكلة تواصل مع الإدارة.' });
});

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS portal_users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(32) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      is_active BOOLEAN NOT NULL DEFAULT FALSE,
      gemini_key_enc TEXT,
      daily_limit INTEGER NOT NULL DEFAULT 50 CHECK (daily_limit > 0),
      opencode_session_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS portal_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS portal_usage_daily (
      user_id BIGINT NOT NULL REFERENCES portal_users(id) ON DELETE CASCADE,
      day DATE NOT NULL DEFAULT CURRENT_DATE,
      requests INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (user_id, day)
    );
  `);
  await pool.query(`INSERT INTO portal_settings (key, value) VALUES ('system_prompt', $1) ON CONFLICT (key) DO NOTHING`, [DEFAULT_PROMPT]);
  const adminUsername = process.env.ADMIN_USERNAME.trim().toLowerCase();
  const admin = await pool.query('SELECT id FROM portal_users WHERE username = $1', [adminUsername]);
  if (!admin.rowCount) {
    const passwordHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
    await pool.query('INSERT INTO portal_users (username, password_hash, is_admin, is_active, daily_limit) VALUES ($1, $2, true, true, 10000)', [adminUsername, passwordHash]);
    console.log('Initial admin account created. Keep ADMIN_PASSWORD secret.');
  }
  await fs.mkdir(DATA_DIR, { recursive: true });
}

try {
  await initializeDatabase();
  console.log('Database initialized.');
} catch (error) {
  console.error(`Startup database initialization failed: ${safeError(error)}`);
  process.exit(1);
}
const server = app.listen(PORT, '0.0.0.0', () => console.log(`Portal listening on ${PORT}`));

setInterval(() => {
  const cutoff = Date.now() - 15 * 60 * 1000;
  for (const [id, job] of jobs.entries()) if (job.createdAt < cutoff && job.status !== 'running') jobs.delete(id);
}, 60 * 1000).unref();

async function shutdown() {
  stopAllInstances();
  server.close();
  await pool.end().catch(() => {});
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
