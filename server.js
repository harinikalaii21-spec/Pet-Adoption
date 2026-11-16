'use strict';
/* =====================================================================
   PawHome backend
   - Node.js built-in http server (no npm packages needed)
   - SQLite database through Node's built-in `node:sqlite` (Node 22.5+)
   - Server-side login (sessions in the database) and permission checks
   ===================================================================== */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = +process.env.PORT || 3000;
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data', 'pawhome.db');
const PUBLIC_DIR = path.join(__dirname, 'public');
const SESSION_DAYS = 7;
const COOKIE = 'pawhome_sid';
const MAX_BODY = 2 * 1024 * 1024;
const MAX_PHOTO_CHARS = 400000;
const MAX_PHOTOS_PER_PET = 5;

/* ---------- database ---------- */
fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
const db = new DatabaseSync(DB_FILE);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
db.exec(fs.readFileSync(path.join(__dirname, 'db', 'schema.sql'), 'utf8'));

// Starter accounts (same as the original demo page). Passwords are stored as
// salted PBKDF2 hashes. admin / 12345, happytails / happytails123.
// CHANGE THE ADMIN PASSWORD after the first login (Dashboard > Profile).
if (!db.prepare('SELECT 1 FROM users LIMIT 1').get()) {
  const ins = db.prepare('INSERT INTO users (username,name,role,email,phone,city,salt,hash,created_at) VALUES (?,?,?,?,?,?,?,?,?)');
  ins.run('admin', 'Admin', 'admin', '', '', '', 'd6b67d57bed7f9cacdce78b0ac909add', 'a8581a00d3c8889582b4c674dffea39a12eef7ee0fae55ee81416c9e2aeaf541', 1760241600000);
  ins.run('happytails', 'Happy Tails Animal Shelter', 'org', '', '', 'Chennai', 'cbd0f560b03e1dfcd962998b53d669ae', '80e4363443dbbb873e24498dfd7427f7ce44c829e83eaa071db57b962ae441e8', 1760241600001);
  ins.run('selene', 'Selene', 'user', '', '', '', 'eef8dc4e9e8a561ac9b5dd7e343c5d2e', '845d667744d06585b7a0941f8977a590ac824da32c45e11f44f0db579199f954', 1760241600002);
  console.log('Database created with starter accounts: admin / 12345 and happytails / happytails123');
}

/* ---------- passwords ---------- */
const hashPw = (pw, saltHex) => crypto.pbkdf2Sync(pw, Buffer.from(saltHex, 'hex'), 100000, 32, 'sha256').toString('hex');
const newSalt = () => crypto.randomBytes(16).toString('hex');
const sameHex = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
function checkPw(user, pw) { return typeof pw === 'string' && pw.length > 0 && sameHex(hashPw(pw, user.salt), user.hash); }

/* ---------- sessions ---------- */
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
function createSession(username) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token_hash,username,expires_at) VALUES (?,?,?)').run(sha(token), username, Date.now() + SESSION_DAYS * 864e5);
  return token;
}
function parseCookies(req) {
  const out = {};
  String(req.headers.cookie || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return out;
}
function currentUser(req) {
  const t = parseCookies(req)[COOKIE]; if (!t) return null;
  const row = db.prepare('SELECT u.* FROM sessions s JOIN users u ON u.username = s.username WHERE s.token_hash = ? AND s.expires_at > ?').get(sha(t), Date.now());
  return row || null;
}
const cookieHeader = (token, maxAge) => `${COOKIE}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
setInterval(() => { try { db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now()); } catch (e) {} }, 36e5).unref();

/* simple login throttle: 10 failures per 15 minutes per ip+username */
const fails = new Map();
function throttled(key) { const f = fails.get(key); return !!f && f.n >= 10 && Date.now() - f.t < 9e5; }
function noteFail(key) { const f = fails.get(key); if (!f || Date.now() - f.t > 9e5) fails.set(key, { n: 1, t: Date.now() }); else f.n++; }

/* ---------- row <-> document mapping (keeps the page's data shape) ---------- */
const COLL = {
  users: { table: 'users', pk: 'username', f: { username: 'username', name: 'name', role: 'role', email: 'email', phone: 'phone', city: 'city', createdAt: 'created_at' } },
  pets: { table: 'pets', pk: 'id', f: { name: 'name', species: 'species', breed: 'breed', color: 'color', gender: 'gender', size: 'size', ageMonths: 'age_months', city: 'city', status: 'status', vaccinated: 'vaccinated', neutered: 'neutered', goodWithKids: 'good_with_kids', houseTrained: 'house_trained', description: 'description', ownerId: 'owner_id', ownerName: 'owner_name', createdAt: 'created_at', updatedAt: 'updated_at' }, bool: ['vaccinated', 'neutered', 'goodWithKids', 'houseTrained'] },
  photos: { table: 'photos', pk: 'id', f: { petId: 'pet_id', ownerId: 'owner_id', data: 'data', live: 'live', takenAt: 'taken_at', order: 'ord', at: 'at' }, bool: ['live'] },
  requests: { table: 'requests', pk: 'id', f: { petId: 'pet_id', petName: 'pet_name', ownerId: 'owner_id', userId: 'user_id', userName: 'user_name', userEmail: 'user_email', phone: 'phone', home: 'home', otherPets: 'other_pets', experience: 'experience', household: 'household', why: 'why', status: 'status', note: 'note', createdAt: 'created_at', updatedAt: 'updated_at' } }
};
function toDoc(coll, row) {
  const c = COLL[coll], d = {};
  for (const [k, col] of Object.entries(c.f)) d[k] = (c.bool && c.bool.includes(k)) ? !!row[col] : row[col];
  if (coll === 'photos') d.data = '/api/photos/' + row.id + '/image';   // images are served separately so the page loads fast
  return d;
}
function upsert(coll, id, values) {
  const c = COLL[coll], cols = Object.keys(values);
  const sql = `INSERT INTO ${c.table} (${c.pk},${cols.join(',')}) VALUES (?,${cols.map(() => '?').join(',')}) ON CONFLICT(${c.pk}) DO UPDATE SET ${cols.map(x => x + '=excluded.' + x).join(',')}`;
  db.prepare(sql).run(id, ...cols.map(k => values[k]));
}
const getRow = (coll, id) => db.prepare(`SELECT * FROM ${COLL[coll].table} WHERE ${COLL[coll].pk} = ?`).get(id);

/* ---------- validation helpers ---------- */
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const bad = m => new HttpError(400, m), forbid = m => new HttpError(403, m || 'You are not allowed to do that.');
const str = (v, max, what) => { v = String(v ?? '').trim(); if (v.length > max) throw bad(`${what || 'Value'} is too long.`); return v; };
const oneOf = (v, list, what) => { if (!list.includes(v)) throw bad(`Invalid ${what}.`); return v; };
const ID_RE = /^[A-Za-z0-9_-]{3,40}$/;
const USERNAME_RE = /^[a-z0-9_.-]{3,24}$/;
const SPECIES = ['dog', 'cat', 'rabbit', 'bird', 'small', 'reptile', 'other'];
const PET_STATUS = ['available', 'reserved', 'adopted'];
const REQ_STATUS = ['pending', 'review', 'approved', 'rejected', 'adopted'];
const ROLES = ['user', 'org', 'admin'];
const isStaff = u => u && (u.role === 'org' || u.role === 'admin');
const adminCount = () => db.prepare("SELECT COUNT(*) n FROM users WHERE role='admin'").get().n;
const needLogin = u => { if (!u) throw new HttpError(401, 'Please log in first.'); return u; };

/* ---------- what each visitor is allowed to see ---------- */
function userView(coll, row, viewer, full) {
  const d = toDoc('users', row);
  if (full) return d;
  const pub = { username: d.username, name: d.name, role: d.role, city: d.city, createdAt: d.createdAt };
  if (d.role === 'org') { pub.email = d.email; pub.phone = d.phone; }   // shelters publish their contact details
  return pub;
}
function bootstrap(viewer) {
  const out = { me: viewer ? userView('users', viewer, viewer, true) : null, users: {}, pets: {}, photos: {}, requests: {} };
  const users = db.prepare('SELECT * FROM users').all();
  const requests = db.prepare('SELECT * FROM requests').all();
  const myAdopters = new Set();
  if (viewer && viewer.role === 'org') requests.forEach(r => { if (r.owner_id === viewer.username) myAdopters.add(r.user_id); });
  for (const u of users) {
    if (viewer && viewer.role === 'admin') out.users[u.username] = toDoc('users', u);
    else if (viewer && u.username === viewer.username) out.users[u.username] = toDoc('users', u);
    else if (u.role === 'org') out.users[u.username] = userView('users', u, viewer, false);
    else if (myAdopters.has(u.username)) { const d = userView('users', u, viewer, false); d.email = u.email; d.phone = u.phone; out.users[u.username] = d; }
  }
  db.prepare('SELECT * FROM pets').all().forEach(r => { out.pets[r.id] = toDoc('pets', r); });
  db.prepare('SELECT id,pet_id,owner_id,live,taken_at,ord,at FROM photos').all().forEach(r => { out.photos[r.id] = toDoc('photos', Object.assign({ data: '' }, r)); });
  for (const r of requests) {
    if (viewer && (viewer.role === 'admin' || r.owner_id === viewer.username || r.user_id === viewer.username)) out.requests[r.id] = toDoc('requests', r);
  }
  return out;
}

/* ---------- write handlers ---------- */
function canEditPet(user, pet) { return user.role === 'admin' || pet.owner_id === user.username; }

function putUser(user, id, body) {
  needLogin(user);
  const target = getRow('users', id); if (!target) throw new HttpError(404, 'User not found.');
  if (user.role !== 'admin' && user.username !== id) throw forbid();
  const v = {
    name: str(body.name, 80, 'Name'), email: str(body.email, 120, 'Email'), phone: str(body.phone, 30, 'Phone'), city: str(body.city, 80, 'City')
  };
  if (!v.name) throw bad('Name cannot be empty.');
  if (v.email && !/^\S+@\S+\.\S+$/.test(v.email)) throw bad('That email address does not look right.');
  if (body.role !== undefined && body.role !== target.role) {
    if (user.role !== 'admin') throw forbid('Only an administrator can change roles.');
    oneOf(body.role, ROLES, 'role');
    if (target.role === 'admin' && adminCount() <= 1) throw bad('There must be at least one administrator.');
    v.role = body.role;
  }
  upsertUpdate('users', id, v);
  if (v.name !== target.name) db.prepare('UPDATE pets SET owner_name = ? WHERE owner_id = ?').run(v.name, id);
  return toDoc('users', getRow('users', id));
}
function upsertUpdate(coll, id, values) {
  const c = COLL[coll], cols = Object.keys(values);
  db.prepare(`UPDATE ${c.table} SET ${cols.map(x => x + '=?').join(',')} WHERE ${c.pk}=?`).run(...cols.map(k => values[k]), id);
}
function createUserRow(f, allowedRoles, minPw) {
  const id = String(f.username || '').trim().toLowerCase();
  if (!USERNAME_RE.test(id)) throw bad('Username must be 3 to 24 characters: letters, numbers, dot, dash or underscore.');
  const name = str(f.name, 80, 'Name'); if (!name) throw bad('Please enter a name.');
  const role = f.role || 'user'; oneOf(role, allowedRoles, 'role');
  const pw = String(f.password || ''); if (pw.length < minPw) throw bad(`Password must be at least ${minPw} characters.`);
  if (pw.length > 200) throw bad('Password is too long.');
  const email = str(f.email, 120, 'Email'); if (email && !/^\S+@\S+\.\S+$/.test(email)) throw bad('That email address does not look right.');
  if (getRow('users', id)) throw new HttpError(409, 'That username is already taken.');
  const salt = newSalt();
  db.prepare('INSERT INTO users (username,name,role,email,phone,city,salt,hash,created_at) VALUES (?,?,?,?,?,?,?,?,?)')
    .run(id, name, role, email, str(f.phone, 30, 'Phone'), str(f.city, 80, 'City'), salt, hashPw(pw, salt), Date.now());
  return id;
}

function putPet(user, id, body) {
  needLogin(user);
  const ex = getRow('pets', id), now = Date.now();
  if (ex) { if (!canEditPet(user, ex)) throw forbid(); }
  else if (!isStaff(user)) throw forbid('Only shelters can list pets.');
  const age = Math.floor(+body.ageMonths);
  if (!(age >= 0 && age <= 600)) throw bad('Invalid age.');
  const v = {
    name: str(body.name, 80, 'Name'), species: oneOf(body.species, SPECIES, 'kind of animal'), breed: str(body.breed, 80, 'Breed'), color: str(body.color, 60, 'Colour'),
    gender: oneOf(body.gender, ['Female', 'Male'], 'gender'), size: oneOf(body.size, ['Small', 'Medium', 'Large'], 'size'), age_months: age,
    city: str(body.city, 80, 'City'), status: oneOf(body.status, PET_STATUS, 'status'),
    vaccinated: body.vaccinated ? 1 : 0, neutered: body.neutered ? 1 : 0, good_with_kids: body.goodWithKids ? 1 : 0, house_trained: body.houseTrained ? 1 : 0,
    description: str(body.description, 2000, 'Description'), updated_at: now
  };
  if (!v.name) throw bad("Please enter the pet's name."); if (!v.city) throw bad('Please enter the city where the pet is.');
  if (!ex) {
    if (!ID_RE.test(id)) throw bad('Invalid id.');
    v.owner_id = user.username; v.owner_name = user.name; v.created_at = now;
  }
  upsert('pets', id, v);
  return toDoc('pets', getRow('pets', id));
}

function putPhoto(user, id, body) {
  needLogin(user);
  const pet = getRow('pets', String(body.petId || '')); if (!pet) throw bad('Pet not found.');
  if (!canEditPet(user, pet)) throw forbid();
  const ex = getRow('photos', id);
  if (ex && ex.pet_id !== pet.id) throw forbid();
  const data = String(body.data || '');
  if (!/^data:image\/(jpeg|png|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(data)) throw bad('That file is not a supported image.');
  if (data.length > MAX_PHOTO_CHARS) throw bad('That photo is too large.');
  if (!ex) {
    if (!ID_RE.test(id)) throw bad('Invalid id.');
    if (db.prepare('SELECT COUNT(*) n FROM photos WHERE pet_id = ?').get(pet.id).n >= MAX_PHOTOS_PER_PET) throw bad(`You can add up to ${MAX_PHOTOS_PER_PET} photos.`);
  }
  upsert('photos', id, { pet_id: pet.id, owner_id: pet.owner_id, data, live: body.live ? 1 : 0, taken_at: Math.floor(+body.takenAt) || Date.now(), ord: Math.floor(+body.order) || Date.now(), at: Math.floor(+body.at) || Date.now() });
  return toDoc('photos', Object.assign({ data: '' }, getRow('photos', id)));
}

function putRequest(user, id, body) {
  needLogin(user);
  const ex = getRow('requests', id), now = Date.now();
  if (ex) {
    // Only the shelter that owns the pet (or an admin) can move a request along
    if (!(user.role === 'admin' || ex.owner_id === user.username)) throw forbid();
    const v = { status: oneOf(body.status, REQ_STATUS, 'status'), note: str(body.note, 500, 'Note'), updated_at: now };
    upsertUpdate('requests', id, v);
  } else {
    const pet = getRow('pets', String(body.petId || '')); if (!pet) throw bad('That pet is no longer listed.');
    if (pet.owner_id === user.username) throw forbid('You cannot request your own pet.');
    if (pet.status === 'adopted') throw bad('This pet has already been adopted.');
    if (!ID_RE.test(id)) throw bad('Invalid id.');
    const dup = db.prepare("SELECT 1 FROM requests WHERE pet_id = ? AND user_id = ? AND status != 'rejected'").get(pet.id, user.username);
    if (dup) throw new HttpError(409, 'You have already sent a request for this pet.');
    const phone = str(body.phone, 30, 'Phone'), why = str(body.why, 2000, 'Message');
    if (phone.replace(/\D/g, '').length < 7) throw bad('Please enter a valid phone number.');
    if (why.length < 20) throw bad('Please write at least a couple of sentences about why you want to adopt.');
    upsert('requests', id, {
      pet_id: pet.id, pet_name: pet.name, owner_id: pet.owner_id, user_id: user.username, user_name: user.name, user_email: user.email || '', phone,
      home: str(body.home, 40, 'Home'), other_pets: str(body.otherPets, 40, 'Other pets'), experience: str(body.experience, 40, 'Experience'), household: str(body.household, 200, 'Household'),
      why, status: 'pending', note: '', created_at: now, updated_at: now
    });
  }
  return toDoc('requests', getRow('requests', id));
}

function delRow(user, coll, id) {
  needLogin(user);
  const row = getRow(coll, id); if (!row) return;
  if (coll === 'pets') { if (!canEditPet(user, row)) throw forbid(); }
  else if (coll === 'photos') { const pet = getRow('pets', row.pet_id); if (!pet || !canEditPet(user, pet)) throw forbid(); }
  else if (coll === 'requests') {
    const own = row.user_id === user.username && (row.status === 'pending' || row.status === 'review');
    if (!(own || user.role === 'admin' || row.owner_id === user.username)) throw forbid();
  } else if (coll === 'users') {
    if (user.role !== 'admin') throw forbid();
    if (id === user.username) throw bad('You cannot delete your own account while signed in.');
    if (row.role === 'admin' && adminCount() <= 1) throw bad('The last administrator cannot be deleted.');
  }
  db.prepare(`DELETE FROM ${COLL[coll].table} WHERE ${COLL[coll].pk} = ?`).run(id);   // related rows go with it (ON DELETE CASCADE)
}

/* ---------- HTTP plumbing ---------- */
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > MAX_BODY) { reject(new HttpError(413, 'That upload is too large.')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { if (!chunks.length) return resolve({}); try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (e) { reject(bad('Invalid request.')); } });
    req.on('error', reject);
  });
}
function send(res, status, obj, headers) {
  const body = JSON.stringify(obj);
  res.writeHead(status, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, headers || {}));
  res.end(body);
}
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.webp': 'image/webp' };
function serveStatic(req, res) {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p === '/') p = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, p));
  if (!file.startsWith(PUBLIC_DIR + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found'); }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff' });
  fs.createReadStream(file).pipe(res);
}

async function api(req, res) {
  const url = new URL(req.url, 'http://x'), parts = url.pathname.split('/').filter(Boolean).slice(1);   // after "api"
  const m = req.method, user = currentUser(req);
  if (m !== 'GET' && !String(req.headers['content-type'] || '').startsWith('application/json') && m !== 'DELETE') throw bad('Invalid request.');
  const body = (m === 'PUT' || m === 'POST') ? await readBody(req) : {};

  if (m === 'GET' && parts[0] === 'bootstrap') return send(res, 200, bootstrap(user));

  if (m === 'GET' && parts[0] === 'photos' && parts[2] === 'image') {
    const row = getRow('photos', parts[1]); if (!row) { res.writeHead(404); return res.end(); }
    const mt = /^data:(image\/[a-z]+);base64,/.exec(row.data);
    res.writeHead(200, { 'Content-Type': mt ? mt[1] : 'image/jpeg', 'Cache-Control': 'public, max-age=86400', 'X-Content-Type-Options': 'nosniff' });
    return res.end(Buffer.from(row.data.slice(row.data.indexOf(',') + 1), 'base64'));
  }

  if (m === 'POST' && parts[0] === 'login') {
    const username = String(body.username || '').trim().toLowerCase(), key = req.socket.remoteAddress + '|' + username;
    if (throttled(key)) throw new HttpError(429, 'Too many attempts. Please wait a few minutes and try again.');
    const u = getRow('users', username);
    if (!u || !checkPw(u, body.password)) { noteFail(key); return send(res, 401, { error: 'Incorrect username or password.' }); }
    fails.delete(key);
    return send(res, 200, { ok: true }, { 'Set-Cookie': cookieHeader(createSession(u.username), SESSION_DAYS * 86400) });
  }
  if (m === 'POST' && parts[0] === 'logout') {
    const t = parseCookies(req)[COOKIE]; if (t) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha(t));
    return send(res, 200, { ok: true }, { 'Set-Cookie': cookieHeader('', 0) });
  }
  if (m === 'POST' && parts[0] === 'register') {
    const id = createUserRow(body, ['user', 'org'], 6);
    return send(res, 201, { ok: true }, { 'Set-Cookie': cookieHeader(createSession(id), SESSION_DAYS * 86400) });
  }
  if (m === 'POST' && parts[0] === 'users' && !parts[1]) {                       // admin creates an account
    needLogin(user); if (user.role !== 'admin') throw forbid();
    const id = createUserRow(body, ROLES, 5);
    return send(res, 201, toDoc('users', getRow('users', id)));
  }
  if (m === 'POST' && parts[0] === 'password' && !parts[1]) {                    // change my own password
    needLogin(user);
    if (!checkPw(user, body.current)) throw bad('Your current password is not correct.');
    const np = String(body.password || ''); if (np.length < 5) throw bad('New password must be at least 5 characters.'); if (np.length > 200) throw bad('Password is too long.');
    const salt = newSalt();
    db.prepare('UPDATE users SET salt=?, hash=? WHERE username=?').run(salt, hashPw(np, salt), user.username);
    return send(res, 200, { ok: true });
  }
  if (m === 'POST' && parts[0] === 'users' && parts[2] === 'password') {        // admin resets someone's password
    needLogin(user); if (user.role !== 'admin') throw forbid();
    const t = getRow('users', parts[1]); if (!t) throw new HttpError(404, 'User not found.');
    const np = String(body.password || ''); if (np.length < 5) throw bad('Password must be at least 5 characters.'); if (np.length > 200) throw bad('Password is too long.');
    const salt = newSalt();
    db.prepare('UPDATE users SET salt=?, hash=? WHERE username=?').run(salt, hashPw(np, salt), t.username);
    db.prepare('DELETE FROM sessions WHERE username = ?').run(t.username);
    return send(res, 200, { ok: true });
  }

  const coll = parts[0], id = parts[1];
  if (['users', 'pets', 'photos', 'requests'].includes(coll) && id) {
    if (m === 'PUT') {
      const h = { users: putUser, pets: putPet, photos: putPhoto, requests: putRequest }[coll];
      return send(res, 200, h(user, id, body));
    }
    if (m === 'DELETE') { delRow(user, coll, id); return send(res, 200, { ok: true }); }
  }
  throw new HttpError(404, 'Not found.');
}

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  try {
    if (req.url.startsWith('/api/')) await api(req, res);
    else if (req.method === 'GET' || req.method === 'HEAD') serveStatic(req, res);
    else { res.writeHead(405); res.end(); }
  } catch (e) {
    if (e instanceof HttpError) { if (!res.headersSent) send(res, e.status, { error: e.message }); }
    else { console.error(e); if (!res.headersSent) send(res, 500, { error: 'Something went wrong on the server.' }); }
  }
});
server.listen(PORT, () => console.log(`PawHome is running at http://localhost:${PORT}`));
