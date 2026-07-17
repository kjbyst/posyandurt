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

// Wrapper untuk memastikan kode lama (callback & ?) tetap berjalan di Postgres
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
  serialize: (fn) => fn() // No-op untuk Postgres
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

// ================== SESSION STORE (Postgres) ==================
app.use(session({
    store: new pgSession({
        pool: pool,
        tableName: 'session'
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
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT, force_reset INTEGER DEFAULT 0
  )`, [], () => {});

  db.run(`CREATE TABLE IF NOT EXISTS warga (
    id TEXT PRIMARY KEY, nama TEXT, nomorRumah TEXT, jenisIuran INTEGER
  )`, [], () => {});

  db.run(`CREATE TABLE IF NOT EXISTS pemasukan (
    id TEXT PRIMARY KEY, wargaId TEXT, namaWarga TEXT, nomorRumah TEXT,
    bulan INTEGER, tahun INTEGER, jumlah INTEGER, tanggal TEXT, ts INTEGER, tipe TEXT
  )`, [], () => {});

  db.run(`CREATE TABLE IF NOT EXISTS pengeluaran (
    id TEXT PRIMARY KEY, keterangan TEXT, jumlah INTEGER, tanggal TEXT, ts INTEGER
  )`, [], () => {});

  db.run(`CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY, userId TEXT, username TEXT, aksi TEXT, target TEXT, detail TEXT, ts INTEGER
  )`, [], () => {});

  // Migrasi kolom (ignore error jika sudah ada)
  db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS force_reset INTEGER DEFAULT 0`, [], () => {});

  // Seed admin awal
  db.get(`SELECT id FROM users WHERE username = ?`, ['admin'], (err, row) => {
    if (err || row) return;
    const initialPassword = crypto.randomBytes(9).toString('base64url');
    bcrypt.hash(initialPassword, 12, (err, hash) => {
      if (err) return;
      db.run(`INSERT INTO users (id, username, password, role, force_reset) VALUES (?, ?, ?, ?, ?)`,
        [crypto.randomUUID(), 'admin', hash, 'administrator', 1]);
      console.log('================================================================');
      console.log(' Admin awal dibuat: admin / ' + initialPassword);
      console.log('================================================================');
    });
  });
});

function logAudit(req, aksi, target, detail) {
  db.run(`INSERT INTO audit_log (id, userId, username, aksi, target, detail, ts) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [crypto.randomUUID(), req.session.userId || null, req.session.username || null, aksi, target || null, detail || null, Date.now()]);
}

/* ============================= AUTH & API (LOGIKA SAMA) ============================= */
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.status(401).json({ message: "Akses ditolak." });
}

function isAdministrator(req, res, next) {
  if (req.session && req.session.role === 'administrator') return next();
  return res.status(403).json({ message: "Akses dilarang." });
}

function isAllowedToMutate(req, res, next) {
  if (req.session && (req.session.role === 'administrator' || req.session.role === 'operator')) return next();
  return res.status(403).json({ message: "Akses dilarang." });
}

function isNonEmptyString(v, maxLen = 150) { return typeof v === 'string' && v.trim().length > 0 && v.trim().length <= maxLen; }
function isPositiveNumber(v) { const n = Number(v); return Number.isFinite(n) && n >= 0; }
function isValidMonth(v) { const n = Number(v); return Number.isInteger(n) && n >= 0 && n <= 11; }
function isValidYear(v) { const n = Number(v); return Number.isInteger(n) && n >= 2000 && n <= 2100; }

// --- Rute API ---
app.post('/api/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  if (!isNonEmptyString(username, 100) || typeof password !== 'string' || password.length === 0) {
    return res.status(400).json({ message: "Username dan password wajib diisi." });
  }

  db.get(`SELECT * FROM users WHERE username = ?`, [username.trim()], async (err, user) => {
    if (err || !user) return res.status(401).json({ message: "Nama pengguna atau kata sandi salah." });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Nama pengguna atau kata sandi salah." });

    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ message: "Gagal membuat sesi." });
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.role = user.role;
      logAudit(req, 'LOGIN', user.id, null);
      return res.json({ id: user.id, username: user.username, role: user.role, forceReset: !!user.force_reset });
    });
  });
});

app.post('/api/logout', isAuthenticated, (req, res) => {
  logAudit(req, 'LOGOUT', req.session.userId, null);
  req.session.destroy(err => {
    res.clearCookie('connect.sid');
    return res.json({ message: "Berhasil keluar." });
  });
});

app.get('/api/data', isAuthenticated, (req, res) => {
  const dataOut = { currentUser: { id: req.session.userId, username: req.session.username, role: req.session.role } };
  db.all(`SELECT id, nama, nomorRumah, jenisIuran FROM warga`, [], (err, wargaRows) => {
    dataOut.warga = wargaRows || [];
    db.all(`SELECT * FROM pemasukan`, [], (err, pemRows) => {
      dataOut.pemasukan = pemRows || [];
      db.all(`SELECT * FROM pengeluaran`, [], (err, pengRows) => {
        dataOut.pengeluaran = pengRows || [];
        let userQuery = `SELECT id, username, '••••••••' as password, role FROM users`;
        let params = [];
        if (req.session.role === 'viewer') { userQuery += ` WHERE id = ?`; params.push(req.session.userId); }
        db.all(userQuery, params, (err, userRows) => {
          dataOut.users = userRows || [];
          res.json(dataOut);
        });
      });
    });
  });
});

// Rute lainnya (warga, pemasukan, pengeluaran, users) tetap sama 
// Karena fungsi db.run/get/all di atas sudah menangani konversi ? ke $1
// Anda tidak perlu mengubah kode di bawah ini.

app.post('/api/warga', isAuthenticated, isAllowedToMutate, (req, res) => {
  const { nama, nomorRumah, jenisIuran } = req.body;
  const id = crypto.randomUUID();
  db.run(`INSERT INTO warga (id, nama, nomorRumah, jenisIuran) VALUES (?, ?, ?, ?)`,
    [id, nama.trim(), nomorRumah.trim(), Number(jenisIuran)], (err) => {
      if (err) return res.status(500).json({ message: "Gagal menyimpan." });
      res.json({ success: true });
    });
});

app.use(session({
  store: new pgSession({
    pool: pgPool, // pastikan pool koneksi Anda sudah terhubung ke Neon
    tableName: 'session',
    createTableIfMissing: true // <--- Tambahkan baris ini
  }),
  secret: 'rahasia-anda',
  resave: false,
  saveUninitialized: false
}));

// ... (Tambahkan rute lainnya di sini dengan logika yang sama)

app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});