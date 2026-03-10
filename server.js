const express  = require('express');
const cors     = require('cors');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path     = require('path');
const crypto   = require('crypto');

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
  CREATE TABLE IF NOT EXISTS user_sessions (
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
  CREATE TABLE IF NOT EXISTS rooms (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    code       TEXT    UNIQUE NOT NULL,
    owner_id   INTEGER NOT NULL,
    names      TEXT    NOT NULL DEFAULT '[]',
    last_pick  TEXT    DEFAULT NULL,
    active     INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (owner_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS room_members (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    room_code TEXT    NOT NULL,
    user_id   INTEGER NOT NULL,
    role      TEXT    NOT NULL DEFAULT 'viewer',
    joined_at TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(room_code, user_id)
  );
`);

// Safe migrations
try { db.exec(`ALTER TABLE users ADD COLUMN username_changed_at TEXT DEFAULT NULL`); } catch {}
// Rename old 'sessions' table to 'user_sessions' if it exists and user_sessions doesn't
try {
  const oldExists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'").get();
  const newExists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='user_sessions'").get();
  if (oldExists && !newExists) {
    db.exec("ALTER TABLE sessions RENAME TO user_sessions");
  }
} catch {}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors({ origin:'*', methods:['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders:['Content-Type','Authorization'] }));
app.use(express.json());

function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return res.status(401).json({ error:'Not authenticated' });
  try { req.user = jwt.verify(header.slice(7), JWT_SECRET); next(); }
  catch { return res.status(401).json({ error:'Invalid or expired token' }); }
}

// ── Auth ──────────────────────────────────────────────────────────────────────
app.post('/auth/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error:'Username and password are required.' });
  if (username.length < 2 || username.length > 30) return res.status(400).json({ error:'Username must be 2–30 characters.' });
  if (password.length < 4) return res.status(400).json({ error:'Password must be at least 4 characters.' });
  if (db.prepare('SELECT id FROM users WHERE username=?').get(username)) return res.status(409).json({ error:'That username is already taken.' });
  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)').run(username, hash, 'viewer');
  const token = jwt.sign({ id:result.lastInsertRowid, username, role:'viewer' }, JWT_SECRET, { expiresIn:'30d' });
  res.json({ token, user:{ id:result.lastInsertRowid, username, role:'viewer' } });
});

app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error:'Username and password are required.' });
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error:'Incorrect username or password.' });
  const token = jwt.sign({ id:user.id, username:user.username, role:user.role }, JWT_SECRET, { expiresIn:'30d' });
  res.json({ token, user:{ id:user.id, username:user.username, role:user.role } });
});

app.get('/auth/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id,username,role,created_at,username_changed_at FROM users WHERE id=?').get(req.user.id);
  if (!user) return res.status(404).json({ error:'User not found.' });
  const sessionCount = db.prepare('SELECT COUNT(*) as count FROM user_sessions WHERE user_id=?').get(user.id);
  let cooldownDaysLeft = 0;
  if (user.username_changed_at) {
    const days = (new Date() - new Date(user.username_changed_at)) / 86400000;
    cooldownDaysLeft = Math.max(0, Math.ceil(USERNAME_COOLDOWN_DAYS - days));
  }
  res.json({ ...user, session_count:sessionCount.count, cooldown_days_left:cooldownDaysLeft });
});

app.put('/auth/username', requireAuth, (req, res) => {
  const { username } = req.body;
  if (!username || username.length < 2 || username.length > 30) return res.status(400).json({ error:'Username must be 2–30 characters.' });
  const user = db.prepare('SELECT username_changed_at FROM users WHERE id=?').get(req.user.id);
  if (user.username_changed_at) {
    const days = (new Date() - new Date(user.username_changed_at)) / 86400000;
    if (days < USERNAME_COOLDOWN_DAYS) {
      const left = Math.ceil(USERNAME_COOLDOWN_DAYS - days);
      return res.status(429).json({ error:`You can change your username again in ${left} day${left!==1?'s':''}.` });
    }
  }
  if (db.prepare('SELECT id FROM users WHERE username=? AND id!=?').get(username, req.user.id)) return res.status(409).json({ error:'That username is already taken.' });
  db.prepare('UPDATE users SET username=?,username_changed_at=? WHERE id=?').run(username, new Date().toISOString(), req.user.id);
  const newToken = jwt.sign({ id:req.user.id, username, role:req.user.role }, JWT_SECRET, { expiresIn:'30d' });
  res.json({ token:newToken, username });
});

app.put('/auth/password', requireAuth, (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) return res.status(400).json({ error:'Password must be at least 4 characters.' });
  db.prepare('UPDATE users SET password=? WHERE id=?').run(bcrypt.hashSync(newPassword,10), req.user.id);
  const newToken = jwt.sign({ id:req.user.id, username:req.user.username, role:req.user.role }, JWT_SECRET, { expiresIn:'30d' });
  res.json({ token:newToken });
});

app.post('/auth/upgrade', requireAuth, (req, res) => {
  const { adminPassword } = req.body;
  const setting = db.prepare("SELECT value FROM settings WHERE key='admin_password_hash'").get();
  if (!setting) return res.status(403).json({ error:'No admin password has been set.' });
  if (!bcrypt.compareSync(adminPassword, setting.value)) return res.status(403).json({ error:'Incorrect admin password.' });
  db.prepare("UPDATE users SET role='admin' WHERE id=?").run(req.user.id);
  db.prepare('INSERT INTO user_sessions (user_id) VALUES (?)').run(req.user.id);
  const newToken = jwt.sign({ id:req.user.id, username:req.user.username, role:'admin' }, JWT_SECRET, { expiresIn:'30d' });
  res.json({ token:newToken, role:'admin' });
});

app.post('/sessions/join', requireAuth, (req, res) => {
  db.prepare('INSERT INTO user_sessions (user_id) VALUES (?)').run(req.user.id);
  res.json({ ok:true });
});

app.get('/sessions/mine', requireAuth, (req, res) => {
  const sessions = db.prepare('SELECT id,joined_at FROM user_sessions WHERE user_id=? ORDER BY joined_at DESC LIMIT 50').all(req.user.id);
  res.json(sessions);
});

app.post('/owner/set-admin-password', (req, res) => {
  const { ownerToken, adminPassword } = req.body;
  if (ownerToken !== (process.env.OWNER_TOKEN||'owner-secret')) return res.status(403).json({ error:'Not authorized.' });
  if (!adminPassword) return res.status(400).json({ error:'Password cannot be empty.' });
  db.prepare("INSERT OR REPLACE INTO settings (key,value) VALUES ('admin_password_hash',?)").run(bcrypt.hashSync(adminPassword,10));
  res.json({ ok:true });
});

app.delete('/owner/remove-admin-password', (req, res) => {
  const { ownerToken } = req.body;
  if (ownerToken !== (process.env.OWNER_TOKEN||'owner-secret')) return res.status(403).json({ error:'Not authorized.' });
  db.prepare("DELETE FROM settings WHERE key='admin_password_hash'").run();
  res.json({ ok:true });
});

// ── Rooms (live sessions) ─────────────────────────────────────────────────────

function genCode() {
  return crypto.randomBytes(3).toString('hex').toUpperCase(); // e.g. A3F9B2
}

// POST /rooms — owner creates a room, seeds it with their name list
app.post('/rooms', requireAuth, (req, res) => {
  const { names } = req.body;
  // Close any existing active rooms for this owner
  db.prepare("UPDATE rooms SET active=0 WHERE owner_id=? AND active=1").run(req.user.id);
  let code;
  do { code = genCode(); } while (db.prepare('SELECT id FROM rooms WHERE code=?').get(code));
  db.prepare('INSERT INTO rooms (code,owner_id,names) VALUES (?,?,?)').run(code, req.user.id, JSON.stringify(names||[]));
  // Log owner as member with owner role
  db.prepare('INSERT OR REPLACE INTO room_members (room_code,user_id,role) VALUES (?,?,?)').run(code, req.user.id, 'owner');
  db.prepare('INSERT INTO user_sessions (user_id) VALUES (?)').run(req.user.id);
  res.json({ code });
});

// GET /rooms/:code — poll room state
app.get('/rooms/:code', requireAuth, (req, res) => {
  const room = db.prepare('SELECT * FROM rooms WHERE code=?').get(req.params.code);
  if (!room) return res.status(404).json({ error:'Room not found.' });
  if (!room.active) return res.status(410).json({ error:'This session has ended.' });
  // Get member list
  const members = db.prepare(`
    SELECT rm.user_id, rm.role, u.username
    FROM room_members rm JOIN users u ON u.id=rm.user_id
    WHERE rm.room_code=?
  `).all(req.params.code);
  // Determine this user's room role
  const me = members.find(m=>m.user_id===req.user.id);
  res.json({
    code: room.code,
    names: JSON.parse(room.names),
    last_pick: room.last_pick,
    active: !!room.active,
    owner_id: room.owner_id,
    my_room_role: me ? me.role : 'viewer',
    member_count: members.length,
    members: members.map(m=>({ username:m.username, role:m.role }))
  });
});

// POST /rooms/:code/join — viewer joins a room
app.post('/rooms/:code/join', requireAuth, (req, res) => {
  const room = db.prepare('SELECT * FROM rooms WHERE code=?').get(req.params.code);
  if (!room) return res.status(404).json({ error:'Room not found.' });
  if (!room.active) return res.status(410).json({ error:'This session has ended.' });
  const existing = db.prepare('SELECT role FROM room_members WHERE room_code=? AND user_id=?').get(req.params.code, req.user.id);
  if (!existing) {
    db.prepare('INSERT INTO room_members (room_code,user_id,role) VALUES (?,?,?)').run(req.params.code, req.user.id, 'viewer');
    db.prepare('INSERT INTO user_sessions (user_id) VALUES (?)').run(req.user.id);
  }
  const myRole = existing ? existing.role : 'viewer';
  res.json({ ok:true, role:myRole });
});

// POST /rooms/:code/admin-join — join as admin using admin password
app.post('/rooms/:code/admin-join', requireAuth, (req, res) => {
  const { adminPassword } = req.body;
  const room = db.prepare('SELECT * FROM rooms WHERE code=?').get(req.params.code);
  if (!room) return res.status(404).json({ error:'Room not found.' });
  if (!room.active) return res.status(410).json({ error:'This session has ended.' });
  const setting = db.prepare("SELECT value FROM settings WHERE key='admin_password_hash'").get();
  if (!setting) return res.status(403).json({ error:'No admin password set.' });
  if (!bcrypt.compareSync(adminPassword, setting.value)) return res.status(403).json({ error:'Incorrect admin password.' });
  db.prepare('INSERT OR REPLACE INTO room_members (room_code,user_id,role) VALUES (?,?,?)').run(req.params.code, req.user.id, 'admin');
  db.prepare('INSERT INTO user_sessions (user_id) VALUES (?)').run(req.user.id);
  res.json({ ok:true, role:'admin' });
});

// PUT /rooms/:code — owner updates names or last_pick
app.put('/rooms/:code', requireAuth, (req, res) => {
  const room = db.prepare('SELECT * FROM rooms WHERE code=?').get(req.params.code);
  if (!room) return res.status(404).json({ error:'Room not found.' });
  if (room.owner_id !== req.user.id) {
    // Allow admins to update names too
    const mem = db.prepare('SELECT role FROM room_members WHERE room_code=? AND user_id=?').get(req.params.code, req.user.id);
    if (!mem || mem.role === 'viewer') return res.status(403).json({ error:'Not authorized.' });
  }
  const { names, last_pick } = req.body;
  if (names !== undefined) db.prepare('UPDATE rooms SET names=? WHERE code=?').run(JSON.stringify(names), req.params.code);
  if (last_pick !== undefined) db.prepare('UPDATE rooms SET last_pick=? WHERE code=?').run(last_pick, req.params.code);
  res.json({ ok:true });
});

// DELETE /rooms/:code — owner ends the session
app.delete('/rooms/:code', requireAuth, (req, res) => {
  const room = db.prepare('SELECT * FROM rooms WHERE code=?').get(req.params.code);
  if (!room) return res.status(404).json({ error:'Room not found.' });
  if (room.owner_id !== req.user.id) return res.status(403).json({ error:'Only the owner can end the session.' });
  db.prepare('UPDATE rooms SET active=0 WHERE code=?').run(req.params.code);
  res.json({ ok:true });
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status:'ok', app:'Name Picker API' }));

app.listen(PORT, () => console.log(`Name Picker API running on port ${PORT}`));
