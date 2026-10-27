require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieSession = require('cookie-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const db = require('./db');

const DOMAIN = (process.env.ALLOWED_DOMAIN || 'upgradetrans.co.zw').toLowerCase();
const SECRET = process.env.SESSION_SECRET;
if (!SECRET || SECRET === 'change-me') { console.error('Set SESSION_SECRET in .env'); process.exit(1); }

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], styleSrc: ["'self'", "'unsafe-inline'"],
  imgSrc: ["'self'", 'data:'], formAction: ["'self'"], frameAncestors: ["'none'"] } } }));
app.use(express.json({ limit: '300kb' }));
app.use(cookieSession({
  name: 'ut_session', keys: [SECRET], maxAge: 12 * 3600 * 1000,
  httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production'
}));

const needAuth = (req, res, next) => {
  if (req.session && req.session.email) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'auth' });
  res.redirect('/login.html');
};

const loginLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true });
app.post('/login', loginLimit, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const pw = String(req.body.password || '');
  const u = email.endsWith('@' + DOMAIN) && db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !bcrypt.compareSync(pw, u.hash)) return res.status(401).json({ error: 'Wrong email or password' });
  req.session = { email: u.email, name: u.name };
  res.json({ ok: true });
});
app.get('/logout', (req, res) => { req.session = null; res.redirect('/login.html'); });

app.get(['/', '/index.html'], needAuth, (req, res) => res.sendFile(path.join(__dirname, 'views', 'index.html')));

app.get('/api/meetings', needAuth, (req, res) => {
  const rows = db.prepare('SELECT id, data FROM meetings').all();
  res.json(rows.map(r => ({ id: r.id, ...JSON.parse(r.data) })));
});
const okId = id => /^[a-z0-9]{4,24}$/.test(id);
app.put('/api/meetings/:id', needAuth, (req, res) => {
  const b = req.body;
  if (!okId(req.params.id) || !b || typeof b !== 'object' || Array.isArray(b)) return res.status(400).json({ error: 'bad request' });
  delete b.id;
  db.prepare(`INSERT INTO meetings(id,data,updated,updated_by) VALUES(?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET data=excluded.data, updated=excluded.updated, updated_by=excluded.updated_by`)
    .run(req.params.id, JSON.stringify(b), Date.now(), req.session.email);
  res.json({ ok: true });
});
app.delete('/api/meetings/:id', needAuth, (req, res) => {
  if (!okId(req.params.id)) return res.status(400).json({ error: 'bad request' });
  db.prepare('DELETE FROM meetings WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, 'public')));
const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Meeting tracker on port ' + port));