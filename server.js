require('dotenv').config();

const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const pgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

// ================== POSTGRESQL SETUP ==================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Wrapper agar kode lama Anda tetap berjalan
const db = {
  run: (sql, params, cb) => {
    let i = 1;
    const pgSql = sql.replace(/\?/g, () => '$' + i++);
    pool.query(pgSql, params, (err, res) => cb ? cb(err) : null);
  },
  get: (sql, params, cb) => {
    let i = 1;
    const pgSql = sql.replace(/\?/g, () => '$' + i++);
    pool.query(pgSql, params, (err, res) => cb(err, res ? res.rows[0] : null));
  },
  all: (sql, params, cb) => {
    let i = 1;
    const pgSql = sql.replace(/\?/g, () => '$' + i++);
    pool.query(pgSql, params, (err, res) => cb(err, res ? res.rows : null));
  },
  serialize: (fn) => fn()
};

const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
  console.error('FATAL: environment variable SESSION_SECRET belum diset.');
  process.exit(1);
}

app.set('trust proxy', 1);

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            frameAncestors: ["'self'"],
        },
    },
}));

app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: true, limit: '200kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ================== SESSION STORE (Diperbaiki) ==================
app.use(session({
    store: new pgSession({
        pool: pool, // Menggunakan variabel 'pool' yang didefinisikan di atas
        tableName: 'session',
        createTableIfMissing: true // Otomatis buat tabel di Neon
    }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: IS_PROD,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 8
    }
}));

// ... (Kode rateLimit, logAudit, dan rute API Anda tetap sama di bawah ini) ...
// Pastikan tidak ada duplikasi app.use(session) di bawahnya!

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Terlalu banyak percobaan login, silakan coba lagi dalam 15 menit." }
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Terlalu banyak permintaan, silakan coba lagi beberapa saat lagi." }
});
app.use('/api/', apiLimiter);

/* ============================= DATABASE SCHEMA INIT ============================= */
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT, force_reset INTEGER DEFAULT 0)`, [], () => {});
  db.run(`CREATE TABLE IF NOT EXISTS warga (id TEXT PRIMARY KEY, nama TEXT, nomorRumah TEXT, jenisIuran INTEGER)`, [], () => {});
  db.run(`CREATE TABLE IF NOT EXISTS pemasukan (id TEXT PRIMARY KEY, wargaId TEXT, namaWarga TEXT, nomorRumah TEXT, bulan INTEGER, tahun INTEGER, jumlah INTEGER, tanggal TEXT, ts INTEGER, tipe TEXT)`, [], () => {});
  db.run(`CREATE TABLE IF NOT EXISTS pengeluaran (id TEXT PRIMARY KEY, keterangan TEXT, jumlah INTEGER, tanggal TEXT, ts INTEGER)`, [], () => {});
  db.run(`CREATE TABLE IF NOT EXISTS audit_log (id TEXT PRIMARY KEY, userId TEXT, username TEXT, aksi TEXT, target TEXT, detail TEXT, ts INTEGER)`, [], () => {});
  db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS force_reset INTEGER DEFAULT 0`, [], () => {});

  db.get(`SELECT id FROM users WHERE username = ?`, ['admin'], (err, row) => {
    if (err || row) return;
    const initialPassword = crypto.randomBytes(9).toString('base64url');
    bcrypt.hash(initialPassword, 12, (err, hash) => {
      if (err) return;
      db.run(`INSERT INTO users (id, username, password, role, force_reset) VALUES (?, ?, ?, ?, ?)`,
        [crypto.randomUUID(), 'admin', hash, 'administrator', 1]);
      console.log('Admin awal dibuat: admin / ' + initialPassword);
    });
  });
});

// ... (Lanjutkan dengan fungsi logAudit dan Rute API Anda seperti semula)

app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});