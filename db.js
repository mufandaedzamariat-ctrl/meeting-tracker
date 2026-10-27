const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');
const file = process.env.DB_FILE || './data/tracker.db';
fs.mkdirSync(path.dirname(file), { recursive: true });
const db = new Database(file);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    hash TEXT NOT NULL,
    created INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS meetings (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    updated INTEGER NOT NULL,
    updated_by TEXT
  );
`);
module.exports = db;