const express  = require('express');
const cors     = require('cors');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path     = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production-please';
const USERNAME_COOLDOWN_DAYS = 7;

// ── Database ──────────────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'data.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    username            TEXT    UNIQUE NOT NULL COLLATE NOCASE,
    password            TEXT    NOT NULL,
    role                TEXT    NOT NULL DEFAULT 'viewer',
    created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
    username_changed_at TEXT    DEFAULT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL,
    joined_at TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS picker_names (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT UNIQUE NOT NULL COLLATE NOCASE,
    added_by INTEGER,
    added_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
  );
`);

// Migrate existing DBs that lack new columns
try { db.exec(`ALTER TABLE users ADD COLUMN username_changed_at TEXT DEFAULT NULL`); } catch {}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors({
  origin: '*',
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));
app.use(express.json());

function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer '))
    return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── Register ──────────────────────────────────────────────────────────────────
app.post('/auth/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password are required.' });
  if (username.length < 2 || username.length > 30)
    return res.status(400).json({ error: 'Username must be 2–30 characters.' });
  if (password.length < 4)
    return res.status(400).json({ error: 'Password must be at least 4 characters.' });

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'That username is already taken.' });

  const hash   = bcrypt.hashSync(password, 10);
  const result = db.prepare(
    'INSERT INTO users (username, password, role) VALUES (?, ?, ?)'
  ).run(username, hash, 'viewer');

  const token = jwt.sign(
    { id: result.lastInsertRowid, username, role: 'viewer' },
    JWT_SECRET, { expiresIn: '30d' }
  );
  res.json({ token, user: { id: result.lastInsertRowid, username, role: 'viewer' } });
});

// ── Login ─────────────────────────────────────────────────────────────────────
app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password are required.' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Incorrect username or password.' });

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET, { expiresIn: '30d' }
  );
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

// ── Me ────────────────────────────────────────────────────────────────────────
app.get('/auth/me', requireAuth, (req, res) => {
  const user = db.prepare(
    'SELECT id, username, role, created_at, username_changed_at FROM users WHERE id = ?'
  ).get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });

  const sessionCount = db.prepare(
    'SELECT COUNT(*) as count FROM sessions WHERE user_id = ?'
  ).get(user.id);

  // Calculate cooldown remaining
  let cooldownDaysLeft = 0;
  if (user.username_changed_at) {
    const changed = new Date(user.username_changed_at);
    const now     = new Date();
    const daysDiff = (now - changed) / (1000 * 60 * 60 * 24);
    cooldownDaysLeft = Math.max(0, Math.ceil(USERNAME_COOLDOWN_DAYS - daysDiff));
  }

  res.json({ ...user, session_count: sessionCount.count, cooldown_days_left: cooldownDaysLeft });
});

// ── Change Username (7-day cooldown) ─────────────────────────────────────────
app.put('/auth/username', requireAuth, (req, res) => {
  const { username } = req.body;
  if (!username || username.length < 2 || username.length > 30)
    return res.status(400).json({ error: 'Username must be 2–30 characters.' });

  const user = db.prepare(
    'SELECT username_changed_at FROM users WHERE id = ?'
  ).get(req.user.id);

  // Enforce 7-day cooldown
  if (user.username_changed_at) {
    const changed  = new Date(user.username_changed_at);
    const now      = new Date();
    const daysDiff = (now - changed) / (1000 * 60 * 60 * 24);
    if (daysDiff < USERNAME_COOLDOWN_DAYS) {
      const daysLeft = Math.ceil(USERNAME_COOLDOWN_DAYS - daysDiff);
      return res.status(429).json({
        error: `You can change your username again in ${daysLeft} day${daysLeft !== 1 ? 's' : ''}.`
      });
    }
  }

  const existing = db.prepare(
    'SELECT id FROM users WHERE username = ? AND id != ?'
  ).get(username, req.user.id);
  if (existing) return res.status(409).json({ error: 'That username is already taken.' });

  const now = new Date().toISOString();
  db.prepare(
    'UPDATE users SET username = ?, username_changed_at = ? WHERE id = ?'
  ).run(username, now, req.user.id);

  const newToken = jwt.sign(
    { id: req.user.id, username, role: req.user.role },
    JWT_SECRET, { expiresIn: '30d' }
  );
  res.json({ token: newToken, username });
});

// ── Change Password ───────────────────────────────────────────────────────────
app.put('/auth/password', requireAuth, (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 4)
    return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, req.user.id);
  const newToken = jwt.sign(
    { id: req.user.id, username: req.user.username, role: req.user.role },
    JWT_SECRET, { expiresIn: '30d' }
  );
  res.json({ token: newToken });
});

// ── Admin upgrade ─────────────────────────────────────────────────────────────
app.post('/auth/upgrade', requireAuth, (req, res) => {
  const { adminPassword } = req.body;
  const setting = db.prepare(
    "SELECT value FROM settings WHERE key = 'admin_password_hash'"
  ).get();
  if (!setting)
    return res.status(403).json({ error: 'No admin password has been set.' });
  if (!bcrypt.compareSync(adminPassword, setting.value))
    return res.status(403).json({ error: 'Incorrect admin password.' });

  db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(req.user.id);
  db.prepare('INSERT INTO sessions (user_id) VALUES (?)').run(req.user.id);

  const newToken = jwt.sign(
    { id: req.user.id, username: req.user.username, role: 'admin' },
    JWT_SECRET, { expiresIn: '30d' }
  );
  res.json({ token: newToken, role: 'admin' });
});

// ── Sessions ──────────────────────────────────────────────────────────────────
app.post('/sessions/join', requireAuth, (req, res) => {
  db.prepare('INSERT INTO sessions (user_id) VALUES (?)').run(req.user.id);
  res.json({ ok: true });
});

app.get('/sessions/mine', requireAuth, (req, res) => {
  const sessions = db.prepare(
    'SELECT id, joined_at FROM sessions WHERE user_id = ? ORDER BY joined_at DESC LIMIT 50'
  ).all(req.user.id);
  res.json(sessions);
});

// ── Picker names (server-side, duplicate prevention) ─────────────────────────
app.get('/names', requireAuth, (req, res) => {
  const names = db.prepare('SELECT name FROM picker_names ORDER BY added_at ASC').all();
  res.json(names.map(r => r.name));
});

app.post('/names', requireAuth, (req, res) => {
  if (!['admin','owner'].includes(req.user.role) &&
      !db.prepare("SELECT value FROM settings WHERE key = 'admin_password_hash'").get()) {
    // allow if no admin password set (open mode)
  }
  const { name } = req.body;
  if (!name || !name.trim())
    return res.status(400).json({ error: 'Name cannot be empty.' });

  const trimmed = name.trim();
  const existing = db.prepare('SELECT id FROM picker_names WHERE name = ?').get(trimmed);
  if (existing)
    return res.status(409).json({ error: `"${trimmed}" is already in the list.` });

  db.prepare(
    'INSERT INTO picker_names (name, added_by) VALUES (?, ?)'
  ).run(trimmed, req.user.id);
  res.json({ ok: true, name: trimmed });
});

app.delete('/names/:name', requireAuth, (req, res) => {
  db.prepare('DELETE FROM picker_names WHERE name = ?').run(
    decodeURIComponent(req.params.name)
  );
  res.json({ ok: true });
});

app.delete('/names', requireAuth, (req, res) => {
  db.prepare('DELETE FROM picker_names').run();
  res.json({ ok: true });
});

// ── Owner: set/remove admin password ─────────────────────────────────────────
app.post('/owner/set-admin-password', (req, res) => {
  const { ownerToken, adminPassword } = req.body;
  if (ownerToken !== (process.env.OWNER_TOKEN || 'owner-secret'))
    return res.status(403).json({ error: 'Not authorized.' });
  if (!adminPassword)
    return res.status(400).json({ error: 'Password cannot be empty.' });
  const hash = bcrypt.hashSync(adminPassword, 10);
  db.prepare(
    "INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password_hash', ?)"
  ).run(hash);
  res.json({ ok: true });
});

app.delete('/owner/remove-admin-password', (req, res) => {
  const { ownerToken } = req.body;
  if (ownerToken !== (process.env.OWNER_TOKEN || 'owner-secret'))
    return res.status(403).json({ error: 'Not authorized.' });
  db.prepare("DELETE FROM settings WHERE key = 'admin_password_hash'").run();
  res.json({ ok: true });
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'ok', app: 'Name Picker API' }));

app.listen(PORT, () => console.log(`Name Picker API running on port ${PORT}`));
