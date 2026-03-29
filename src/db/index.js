const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const dataRoot = process.env.DATA_ROOT_DIR || (process.env.VERCEL ? '/tmp' : process.cwd());
const dataDir = path.join(dataRoot, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const dbPath = path.join(dataDir, 'app.db');
const db = new Database(dbPath);

const schemaSql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
db.exec(schemaSql);

module.exports = db;
