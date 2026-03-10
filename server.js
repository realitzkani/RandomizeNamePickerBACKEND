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
const COOLDOWN_DAYS = 7;

// ── Database ──────────────────────────────────────────────────────────────────
let db;
try {
  db = new Database(path.join(__dirname, 'data.db'));
} catch(e) {
  console.error('DB open failed:', e);
  process.exit(1);
}

// Run each statement individually so one failure doesn't block the rest
const schema = [
  `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    username_changed_at TEXT DEFAULT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS user_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    joined_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`,
  `CREATE TABLE IF NOT EXISTS picker_names (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL COLLATE NOCASE,
    added_by INTEGER,
    added_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`,
  `CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  )`,
  `CREATE TABLE IF NOT EXISTS rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    owner_id INTEGER NOT NULL,
    names TEXT NOT NULL DEFAULT '[]',
    last_pick TEXT DEFAULT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (owner_id) REFERENCES users(id)
  )`,
  `CREATE TABLE IF NOT EXISTS room_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_code TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    joined_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(room_code, user_id)
  )`
];

schema.forEach(sql => { try { db.exec(sql); } catch(e) { console.error('Schema error:', e.message); } });

// Migrations — all wrapped safely
const migrations = [
  `ALTER TABLE users ADD COLUMN username_changed_at TEXT DEFAULT NULL`,
  // Copy old 'sessions' data into user_sessions if needed
  `INSERT OR IGNORE INTO user_sessions (id, user_id, joined_at)
   SELECT id, user_id, joined_at FROM sessions`
];
migrations.forEach(sql => { try { db.exec(sql); } catch {} });

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors({ origin:'*', methods:['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders:['Content-Type','Authorization'] }));
app.use(express.json());

// Global error handler — always returns JSON, never HTML
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

function requireAuth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error:'Not authenticated' });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { return res.status(401).json({ error:'Invalid or expired token' }); }
}

function wrap(fn) {
  return async (req, res, next) => {
    try { await fn(req, res, next); }
    catch(e) { console.error(e); res.status(500).json({ error: e.message || 'Server error' }); }
  };
}

// ── Auth ──────────────────────────────────────────────────────────────────────
app.post('/auth/register', wrap((req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error:'Username and password are required.' });
  if (username.length < 2 || username.length > 30) return res.status(400).json({ error:'Username must be 2–30 characters.' });
  if (password.length < 4) return res.status(400).json({ error:'Password must be at least 4 characters.' });
  if (db.prepare('SELECT id FROM users WHERE username=?').get(username)) return res.status(409).json({ error:'That username is already taken.' });
  const hash = bcrypt.hashSync(password, 10);
  const r = db.prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)').run(username, hash, 'viewer');
  const token = jwt.sign({ id:r.lastInsertRowid, username, role:'viewer' }, JWT_SECRET, { expiresIn:'30d' });
  res.json({ token, user:{ id:r.lastInsertRowid, username, role:'viewer' } });
}));

app.post('/auth/login', wrap((req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error:'Username and password are required.' });
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error:'Incorrect username or password.' });
  const token = jwt.sign({ id:user.id, username:user.username, role:user.role }, JWT_SECRET, { expiresIn:'30d' });
  res.json({ token, user:{ id:user.id, username:user.username, role:user.role } });
}));

app.get('/auth/me', requireAuth, wrap((req, res) => {
  const user = db.prepare('SELECT id,username,role,created_at,username_changed_at FROM users WHERE id=?').get(req.user.id);
  if (!user) return res.status(404).json({ error:'User not found.' });
  const sc = db.prepare('SELECT COUNT(*) as c FROM user_sessions WHERE user_id=?').get(user.id);
  let cdLeft = 0;
  if (user.username_changed_at) {
    const days = (Date.now() - new Date(user.username_changed_at)) / 86400000;
    cdLeft = Math.max(0, Math.ceil(COOLDOWN_DAYS - days));
  }
  res.json({ ...user, session_count:sc.c, cooldown_days_left:cdLeft });
}));

app.put('/auth/username', requireAuth, wrap((req, res) => {
  const { username } = req.body;
  if (!username || username.length < 2 || username.length > 30) return res.status(400).json({ error:'Username must be 2–30 characters.' });
  const user = db.prepare('SELECT username_changed_at FROM users WHERE id=?').get(req.user.id);
  if (user.username_changed_at) {
    const days = (Date.now() - new Date(user.username_changed_at)) / 86400000;
    if (days < COOLDOWN_DAYS) {
      const left = Math.ceil(COOLDOWN_DAYS - days);
      return res.status(429).json({ error:`You can change your username again in ${left} day${left!==1?'s':''}.` });
    }
  }
  if (db.prepare('SELECT id FROM users WHERE username=? AND id!=?').get(username, req.user.id)) return res.status(409).json({ error:'That username is already taken.' });
  db.prepare('UPDATE users SET username=?,username_changed_at=? WHERE id=?').run(username, new Date().toISOString(), req.user.id);
  const token = jwt.sign({ id:req.user.id, username, role:req.user.role }, JWT_SECRET, { expiresIn:'30d' });
  res.json({ token, username });
}));

app.put('/auth/password', requireAuth, wrap((req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) return res.status(400).json({ error:'Password must be at least 4 characters.' });
  db.prepare('UPDATE users SET password=? WHERE id=?').run(bcrypt.hashSync(newPassword, 10), req.user.id);
  const token = jwt.sign({ id:req.user.id, username:req.user.username, role:req.user.role }, JWT_SECRET, { expiresIn:'30d' });
  res.json({ token });
}));

app.post('/auth/upgrade', requireAuth, wrap((req, res) => {
  const { adminPassword } = req.body;
  const setting = db.prepare("SELECT value FROM settings WHERE key='admin_password_hash'").get();
  if (!setting) return res.status(403).json({ error:'No admin password has been set.' });
  if (!bcrypt.compareSync(adminPassword, setting.value)) return res.status(403).json({ error:'Incorrect admin password.' });
  db.prepare("UPDATE users SET role='admin' WHERE id=?").run(req.user.id);
  db.prepare('INSERT INTO user_sessions (user_id) VALUES (?)').run(req.user.id);
  const token = jwt.sign({ id:req.user.id, username:req.user.username, role:'admin' }, JWT_SECRET, { expiresIn:'30d' });
  res.json({ token, role:'admin' });
}));

app.post('/sessions/join', requireAuth, wrap((req, res) => {
  db.prepare('INSERT INTO user_sessions (user_id) VALUES (?)').run(req.user.id);
  res.json({ ok:true });
}));

app.get('/sessions/mine', requireAuth, wrap((req, res) => {
  const rows = db.prepare('SELECT id,joined_at FROM user_sessions WHERE user_id=? ORDER BY joined_at DESC LIMIT 50').all(req.user.id);
  res.json(rows);
}));

app.post('/owner/set-admin-password', wrap((req, res) => {
  const { ownerToken, adminPassword } = req.body;
  if (ownerToken !== (process.env.OWNER_TOKEN||'owner-secret')) return res.status(403).json({ error:'Not authorized.' });
  if (!adminPassword) return res.status(400).json({ error:'Password cannot be empty.' });
  db.prepare("INSERT OR REPLACE INTO settings (key,value) VALUES ('admin_password_hash',?)").run(bcrypt.hashSync(adminPassword, 10));
  res.json({ ok:true });
}));

app.delete('/owner/remove-admin-password', wrap((req, res) => {
  const { ownerToken } = req.body;
  if (ownerToken !== (process.env.OWNER_TOKEN||'owner-secret')) return res.status(403).json({ error:'Not authorized.' });
  db.prepare("DELETE FROM settings WHERE key='admin_password_hash'").run();
  res.json({ ok:true });
}));

// ── Rooms ─────────────────────────────────────────────────────────────────────
function genCode() {
  return crypto.randomBytes(3).toString('hex').toUpperCase();
}

app.post('/rooms', requireAuth, wrap((req, res) => {
  const { names } = req.body;
  db.prepare("UPDATE rooms SET active=0 WHERE owner_id=? AND active=1").run(req.user.id);
  let code;
  do { code = genCode(); } while (db.prepare('SELECT id FROM rooms WHERE code=?').get(code));
  db.prepare('INSERT INTO rooms (code,owner_id,names) VALUES (?,?,?)').run(code, req.user.id, JSON.stringify(names||[]));
  db.prepare('INSERT OR REPLACE INTO room_members (room_code,user_id,role) VALUES (?,?,?)').run(code, req.user.id, 'owner');
  db.prepare('INSERT INTO user_sessions (user_id) VALUES (?)').run(req.user.id);
  res.json({ code });
}));

app.get('/rooms/:code', requireAuth, wrap((req, res) => {
  const room = db.prepare('SELECT * FROM rooms WHERE code=?').get(req.params.code);
  if (!room) return res.status(404).json({ error:'Room not found.' });
  if (!room.active) return res.status(410).json({ error:'This session has ended.' });
  const members = db.prepare(
    `SELECT rm.user_id, rm.role, u.username FROM room_members rm
     JOIN users u ON u.id=rm.user_id WHERE rm.room_code=?`
  ).all(req.params.code);
  const me = members.find(m => m.user_id === req.user.id);
  res.json({
    code: room.code,
    names: JSON.parse(room.names),
    last_pick: room.last_pick,
    active: !!room.active,
    owner_id: room.owner_id,
    my_room_role: me ? me.role : 'viewer',
    member_count: members.length,
    members: members.map(m => ({ username:m.username, role:m.role }))
  });
}));

app.post('/rooms/:code/join', requireAuth, wrap((req, res) => {
  const room = db.prepare('SELECT * FROM rooms WHERE code=?').get(req.params.code);
  if (!room) return res.status(404).json({ error:'Room not found.' });
  if (!room.active) return res.status(410).json({ error:'This session has ended.' });
  const existing = db.prepare('SELECT role FROM room_members WHERE room_code=? AND user_id=?').get(req.params.code, req.user.id);
  if (!existing) {
    db.prepare('INSERT INTO room_members (room_code,user_id,role) VALUES (?,?,?)').run(req.params.code, req.user.id, 'viewer');
    db.prepare('INSERT INTO user_sessions (user_id) VALUES (?)').run(req.user.id);
  }
  res.json({ ok:true, role: existing ? existing.role : 'viewer' });
}));

app.post('/rooms/:code/admin-join', requireAuth, wrap((req, res) => {
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
}));

app.put('/rooms/:code', requireAuth, wrap((req, res) => {
  const room = db.prepare('SELECT * FROM rooms WHERE code=?').get(req.params.code);
  if (!room) return res.status(404).json({ error:'Room not found.' });
  if (room.owner_id !== req.user.id) {
    const mem = db.prepare('SELECT role FROM room_members WHERE room_code=? AND user_id=?').get(req.params.code, req.user.id);
    if (!mem || mem.role === 'viewer') return res.status(403).json({ error:'Not authorized.' });
  }
  const { names, last_pick } = req.body;
  if (names !== undefined) db.prepare('UPDATE rooms SET names=? WHERE code=?').run(JSON.stringify(names), req.params.code);
  if (last_pick !== undefined) db.prepare('UPDATE rooms SET last_pick=? WHERE code=?').run(last_pick, req.params.code);
  res.json({ ok:true });
}));

app.delete('/rooms/:code', requireAuth, wrap((req, res) => {
  const room = db.prepare('SELECT * FROM rooms WHERE code=?').get(req.params.code);
  if (!room) return res.status(404).json({ error:'Room not found.' });
  if (room.owner_id !== req.user.id) return res.status(403).json({ error:'Only the owner can end the session.' });
  db.prepare('UPDATE rooms SET active=0 WHERE code=?').run(req.params.code);
  res.json({ ok:true });
}));

// POST /rooms/:code/leave — remove member from room
app.post('/rooms/:code/leave', requireAuth, wrap((req, res) => {
  db.prepare('DELETE FROM room_members WHERE room_code=? AND user_id=?').run(req.params.code, req.user.id);
  res.json({ ok:true });
}));

// ── Names ─────────────────────────────────────────────────────────────────────
app.get('/names', requireAuth, wrap((req, res) => {
  res.json(db.prepare('SELECT name FROM picker_names ORDER BY added_at').all().map(r=>r.name));
}));

app.post('/names', requireAuth, wrap((req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error:'Name required.' });
  if (db.prepare('SELECT id FROM picker_names WHERE name=?').get(name)) return res.status(409).json({ error:'That name already exists.' });
  db.prepare('INSERT INTO picker_names (name,added_by) VALUES (?,?)').run(name, req.user.id);
  res.json({ ok:true });
}));

app.delete('/names/:name', requireAuth, wrap((req, res) => {
  db.prepare('DELETE FROM picker_names WHERE name=?').run(decodeURIComponent(req.params.name));
  res.json({ ok:true });
}));

app.delete('/names', requireAuth, wrap((req, res) => {
  db.prepare('DELETE FROM picker_names').run();
  res.json({ ok:true });
}));

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status:'ok', app:'Name Picker API' }));

app.listen(PORT, () => console.log(`Name Picker API on port ${PORT}`));
