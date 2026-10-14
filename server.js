const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const scrypt = promisify(crypto.scrypt);
const dataFile = path.join(__dirname, 'accounts.json');
const sessions = new Map();
const lifts = ['Barbell back squat', 'Barbell front squat', 'Safety bar squat', 'Barbell bench press', 'Dumbbell bench press', 'Trap bar deadlift'];
if (!fs.existsSync(dataFile)) fs.writeFileSync(dataFile, '[]\n');
function read() {
  const data = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
  if (!Array.isArray(data)) throw new Error('accounts.json must contain an array');
  return data;
}
read();
function write(data) {
  fs.writeFileSync(dataFile + '.tmp', JSON.stringify(data, null, 2) + '\n');
  fs.renameSync(dataFile + '.tmp', dataFile);
}
function publicAccount(a) { return { id: a.id, name: a.name, role: a.role, entries: a.entries }; }
function reply(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}
async function body(req) {
  let value = '';
  for await (const chunk of req) {
    value += chunk;
    if (Buffer.byteLength(value) > 16384) throw new Error('Request too large');
  }
  return JSON.parse(value || '{}');
}
function session(req) {
  const token = (req.headers.cookie || '').split(';').map(v => v.trim()).find(v => v.startsWith('session='))?.slice(8);
  const value = sessions.get(token);
  if (!value || value.expires < Date.now()) { sessions.delete(token); return null; }
  return { token, ...value };
}
function startSession(res, account) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { id: account.id, expires: Date.now() + 86400000 });
  res.setHeader('Set-Cookie', `session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400`);
}
const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  try {
    const url = new URL(req.url, 'http://localhost');
    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(fs.readFileSync(path.join(__dirname, 'index.html')));
    }
    if (!url.pathname.startsWith('/api/')) return reply(res, 404, { error: 'Not found' });
    if (req.method !== 'GET' && req.headers.origin && req.headers.origin !== `http://${req.headers.host}`) return reply(res, 403, { error: 'Request origin rejected' });
    if (req.method === 'POST' && ['/api/register', '/api/login'].includes(url.pathname)) {
      const data = await body(req);
      const name = typeof data.name === 'string' ? data.name.trim().replace(/\s+/g, ' ') : '';
      if (!name || name.length > 80 || !['player', 'coach'].includes(data.role)) return reply(res, 400, { error: 'Enter a name and choose a role.' });
      const password = typeof data.password === 'string' ? data.password : '';
      if (password.length > 1024) return reply(res, 400, { error: 'Password is too long.' });
      let accounts = read();
      let account = accounts.find(a => a.name.toLowerCase() === name.toLowerCase() && a.role === data.role);
      if (url.pathname === '/api/register') {
        if (account) return reply(res, 409, { error: 'Account already exists. Log in instead.' });
        if (data.role === 'coach' && password.length < 8) return reply(res, 400, { error: 'Coach passwords need at least 8 characters.' });
        account = { id: crypto.randomUUID(), name, role: data.role, entries: [] };
        if (data.role === 'coach') {
          account.passwordSalt = crypto.randomBytes(16).toString('hex');
          account.passwordHash = (await scrypt(password, account.passwordSalt, 64)).toString('hex');
        }
        // Re-read after hashing to preserve other requests' changes.
        accounts = read();
        if (accounts.some(a => a.name.toLowerCase() === name.toLowerCase() && a.role === data.role)) return reply(res, 409, { error: 'Account already exists.' });
        write([...accounts, account]);
      } else {
        if (!account) return reply(res, 401, { error: 'Account not found.' });
        if (account.role === 'coach') {
          if (!account.passwordSalt || !account.passwordHash) return reply(res, 401, { error: 'This coach account has no valid password configured.' });
          const hash = await scrypt(password, account.passwordSalt, 64);
          const saved = Buffer.from(account.passwordHash, 'hex');
          if (saved.length !== hash.length || !crypto.timingSafeEqual(saved, hash)) return reply(res, 401, { error: 'Incorrect password.' });
          account = read().find(a => a.id === account.id);
          if (!account) return reply(res, 401, { error: 'Account removed.' });
        }
      }
      startSession(res, account);
      return reply(res, 200, publicAccount(account));
    }
    const active = session(req);
    const accounts = read();
    const account = active && accounts.find(a => a.id === active.id);
    if (!account) return reply(res, 401, { error: 'Please log in.' });
    if (req.method === 'GET' && url.pathname === '/api/me') return reply(res, 200, publicAccount(account));
    if (req.method === 'POST' && url.pathname === '/api/logout') {
      sessions.delete(active.token);
      res.setHeader('Set-Cookie', 'session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
      return reply(res, 200, { ok: true });
    }
    if (req.method === 'GET' && url.pathname === '/api/players') {
      if (account.role !== 'coach') return reply(res, 403, { error: 'Coaches only.' });
      return reply(res, 200, accounts.filter(a => a.role === 'player').map(publicAccount));
    }
    if (req.method === 'POST' && url.pathname === '/api/lifts') {
      if (account.role !== 'player') return reply(res, 403, { error: 'Only players can log lifts.' });
      const data = await body(req);
      if (typeof data.date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(data.date) || Number.isNaN(Date.parse(data.date)) || !lifts.includes(data.lift) || !['lb', 'kg'].includes(data.unit) || !Number.isFinite(data.weight) || data.weight < 0 || !Number.isInteger(data.sets) || data.sets < 1 || !Number.isInteger(data.reps) || data.reps < 1) return reply(res, 400, { error: 'Enter valid lift details.' });
      const latest = read();
      const player = latest.find(a => a.id === account.id && a.role === 'player');
      if (!player) return reply(res, 401, { error: 'Please log in again.' });
      player.entries.unshift({ id: crypto.randomUUID(), date: data.date, lift: data.lift, weight: data.weight, unit: data.unit, sets: data.sets, reps: data.reps });
      write(latest);
      return reply(res, 200, publicAccount(player));
    }
    if (req.method === 'DELETE' && url.pathname.startsWith('/api/lifts/')) {
      if (account.role !== 'player') return reply(res, 403, { error: 'Only players can delete their own lifts.' });
      account.entries = account.entries.filter(e => e.id !== url.pathname.slice('/api/lifts/'.length));
      write(accounts);
      return reply(res, 200, publicAccount(account));
    }
    reply(res, 404, { error: 'Not found' });
  } catch (error) {
    console.error(error.message);
    reply(res, error instanceof SyntaxError ? 400 : 500, { error: 'Unable to complete request. Check the server and accounts file.' });
  }
});
const port = Number(process.env.PORT || 3000);

server.listen(port, process.env.HOST || "127.0.0.1", () => {
  const actualPort = server.address().port;
  console.log(`Lift Tracker: http://localhost:${actualPort}`);
});
