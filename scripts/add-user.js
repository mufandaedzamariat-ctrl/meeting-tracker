require('dotenv').config();
// Usage: npm run add-user -- name@upgradetrans.co.zw "Full Name" "password"
const bcrypt = require('bcryptjs');
const db = require('../db');
const DOMAIN = (process.env.ALLOWED_DOMAIN || 'upgradetrans.co.zw').toLowerCase();
const [email, name, password] = process.argv.slice(2);
if (!email || !name || !password) { console.error('Usage: npm run add-user -- email "Name" "password"'); process.exit(1); }
if (!email.toLowerCase().endsWith('@' + DOMAIN)) { console.error('Email must end with @' + DOMAIN); process.exit(1); }
if (password.length < 10) { console.error('Password must be at least 10 characters'); process.exit(1); }
db.prepare(`INSERT INTO users(email,name,hash,created) VALUES(?,?,?,?)
  ON CONFLICT(email) DO UPDATE SET name=excluded.name, hash=excluded.hash`)
  .run(email.toLowerCase(), name, bcrypt.hashSync(password, 12), Date.now());
console.log('Saved user ' + email);