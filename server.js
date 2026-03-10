const express  = require('express');
const cors     = require('cors');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path     = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production-please';

// ── Database setup ────────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'data.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    UNIQUE NOT NULL COLLATE NOCASE,
    password   TEXT    NOT NULL,
    role       TEXT    NOT NULL DEFAULT 'viewer',
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    joined_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors({
  origin: '*',
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));
app.use(express.json());

// Auth middleware
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── Auth routes ───────────────────────────────────────────────────────────────

// POST /auth/register
app.post('/auth/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  if (username.length < 2 || username.length > 30) {
    return res.status(400).json({ error: 'Username must be 2–30 characters.' });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    return res.status(409).json({ error: 'That username is already taken.' });
  }

  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare(
    'INSERT INTO users (username, password, role) VALUES (?, ?, ?)'
  ).run(username, hash, 'viewer');

  const token = jwt.sign(
    { id: result.lastInsertRowid, username, role: 'viewer' },
    JWT_SECRET,
    { expiresIn: '30d' }
  );

  res.json({ token, user: { id: result.lastInsertRowid, username, role: 'viewer' } });
});

// POST /auth/login
app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '30d' }
  );

  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

// GET /auth/me — verify token and get current user info
app.get('/auth/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, username, role, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });

  const sessionCount = db.prepare('SELECT COUNT(*) as count FROM sessions WHERE user_id = ?').get(user.id);
  res.json({ ...user, session_count: sessionCount.count });
});

// PUT /auth/username — change username
app.put('/auth/username', requireAuth, (req, res) => {
  const { username } = req.body;
  if (!username || username.length < 2 || username.length > 30) {
    return res.status(400).json({ error: 'Username must be 2–30 characters.' });
  }
  const existing = db.prepare('SELECT id FROM users WHERE username = ? AND id != ?').get(username, req.user.id);
  if (existing) return res.status(409).json({ error: 'That username is already taken.' });

  db.prepare('UPDATE users SET username = ? WHERE id = ?').run(username, req.user.id);

  const newToken = jwt.sign(
    { id: req.user.id, username, role: req.user.role },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
  res.json({ token: newToken, username });
});

// ── Role upgrade (admin invite) ───────────────────────────────────────────────

// POST /auth/upgrade — upgrade viewer to admin using admin password
app.post('/auth/upgrade', requireAuth, (req, res) => {
  const { adminPassword } = req.body;

  // Admin password is stored as a hashed value in a settings table
  const setting = db.prepare("SELECT value FROM settings WHERE key = 'admin_password_hash'").get();
  if (!setting) {
    return res.status(403).json({ error: 'No admin password has been set.' });
  }

  if (!bcrypt.compareSync(adminPassword, setting.value)) {
    return res.status(403).json({ error: 'Incorrect admin password.' });
  }

  db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(req.user.id);

  const newToken = jwt.sign(
    { id: req.user.id, username: req.user.username, role: 'admin' },
    JWT_SECRET,
    { expiresIn: '30d' }
  );

  // Log session
  db.prepare('INSERT INTO sessions (user_id) VALUES (?)').run(req.user.id);

  res.json({ token: newToken, role: 'admin' });
});

// ── Session tracking ──────────────────────────────────────────────────────────

// POST /sessions/join — log that a user joined a session
app.post('/sessions/join', requireAuth, (req, res) => {
  db.prepare('INSERT INTO sessions (user_id) VALUES (?)').run(req.user.id);
  res.json({ ok: true });
});

// GET /sessions/mine — get this user's session history
app.get('/sessions/mine', requireAuth, (req, res) => {
  const sessions = db.prepare(
    'SELECT id, joined_at FROM sessions WHERE user_id = ? ORDER BY joined_at DESC LIMIT 50'
  ).all(req.user.id);
  res.json(sessions);
});

// ── Owner-only: set admin password ───────────────────────────────────────────
// This is called from the frontend when the owner sets/updates the admin password.
// It requires the owner's special owner token (set via env var).

app.post('/owner/set-admin-password', (req, res) => {
  const { ownerToken, adminPassword } = req.body;
  const validOwnerToken = process.env.OWNER_TOKEN || 'owner-secret';

  if (ownerToken !== validOwnerToken) {
    return res.status(403).json({ error: 'Not authorized.' });
  }
  if (!adminPassword || adminPassword.length < 1) {
    return res.status(400).json({ error: 'Password cannot be empty.' });
  }

  // Ensure settings table exists
  db.exec(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`);

  const hash = bcrypt.hashSync(adminPassword, 10);
  db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password_hash', ?)").run(hash);

  res.json({ ok: true });
});

app.delete('/owner/remove-admin-password', (req, res) => {
  const { ownerToken } = req.body;
  const validOwnerToken = process.env.OWNER_TOKEN || 'owner-secret';
  if (ownerToken !== validOwnerToken) return res.status(403).json({ error: 'Not authorized.' });

  db.exec(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`);
  db.prepare("DELETE FROM settings WHERE key = 'admin_password_hash'").run();
  res.json({ ok: true });
});

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'ok', app: 'Name Picker API' }));

// ── Start ─────────────────────────────────────────────────────────────────────
// Ensure settings table exists on startup
db.exec(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`);

app.listen(PORT, () => console.log(`Name Picker API running on port ${PORT}`));
