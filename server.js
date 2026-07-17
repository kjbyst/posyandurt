// Memuat variabel dari file .env (jika ada) ke process.env.
// Tanpa ini, Node.js TIDAK akan pernah membaca isi file .env secara otomatis.
require('dotenv').config();

const express = require('express');
const session = require('express-session');
// ================== PERUBAHAN KE NEON: Menggunakan pg & connect-pg-simple ==================
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');

const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

// ================== FIX #1: SESSION_SECRET wajib diset via environment ==================
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
  console.error('FATAL: environment variable SESSION_SECRET belum diset. Set nilai acak yang panjang, contoh:');
  console.error('  export SESSION_SECRET=$(node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))")');
  process.exit(1);
}

// ================== PERUBAHAN KE NEON: Setup PostgreSQL Pool ==================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Wajib untuk layanan cloud seperti Neon
});

pool.connect()
  .then(() => console.log('Terhubung ke database PostgreSQL (Neon).'))
  .catch(err => console.error('Gagal terhubung ke database:', err.message));

// Diperlukan agar cookie "secure" bekerja benar saat app berjalan di belakang
// reverse proxy / load balancer (Nginx, Heroku, dsb.) dengan HTTPS di depannya.
app.set('trust proxy', 1);

// 1. Keamanan Header HTTP (Helmet)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:"],
            // FIX #2: connectSrc tidak lagi wildcard "*".
            connectSrc: ["'self'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            frameAncestors: ["'self'"],
        },
    },
    // FIX #3: header isolasi cross-origin dikembalikan ke default helmet
}));

// 2. Parsing Data Middleware
app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: true, limit: '200kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ================== FIX #4: Session store persisten dengan PostgreSQL ==================
app.use(session({
    store: new pgSession({
        pool: pool,
        tableName: 'sessions', // Akan otomatis dibuat jika menggunakan parameter di bawah
        createTableIfMissing: true
    }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        // FIX #5: cookie sesi wajib "secure" di production
        secure: IS_PROD,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 8 // sesi otomatis kedaluwarsa setelah 8 jam
    }
}));

// 4. Rate Limiter khusus Login (Anti Brute Force)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Terlalu banyak percobaan login, silakan coba lagi dalam 15 menit." }
});

// ================== FIX #6: Rate limiter global untuk seluruh /api ==================
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Terlalu banyak permintaan, silakan coba lagi beberapa saat lagi." }
});
app.use('/api/', apiLimiter);

/* ============================= DATABASE SETUP (POSTGRESQL) ============================= */
// Mengganti db.serialize dengan async function saat booting
async function initDb() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT, force_reset INTEGER DEFAULT 0
    )`);

    // Catatan: Gunakan tanda kutip ganda ("") untuk kolom camelCase agar PostgreSQL tidak mengubahnya jadi lowercase
    await pool.query(`CREATE TABLE IF NOT EXISTS warga (
      id TEXT PRIMARY KEY, nama TEXT, "nomorRumah" TEXT, "jenisIuran" INTEGER
    )`);
    
    // ts (timestamp) menggunakan BIGINT karena Date.now() terlalu besar untuk standard INTEGER
    await pool.query(`CREATE TABLE IF NOT EXISTS pemasukan (
      id TEXT PRIMARY KEY, "wargaId" TEXT, "namaWarga" TEXT, "nomorRumah" TEXT,
      bulan INTEGER, tahun INTEGER, jumlah INTEGER, tanggal TEXT, ts BIGINT, tipe TEXT
    )`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS pengeluaran (
      id TEXT PRIMARY KEY, keterangan TEXT, jumlah INTEGER, tanggal TEXT, ts BIGINT
    )`);
    
    // FIX #7: audit log
    await pool.query(`CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY, "userId" TEXT, username TEXT, aksi TEXT, target TEXT, detail TEXT, ts BIGINT
    )`);

    // FIX #8: password default admin
    const adminCheck = await pool.query(`SELECT id FROM users WHERE username = $1`, ['admin']);
    if (adminCheck.rowCount === 0) {
      const initialPassword = crypto.randomBytes(9).toString('base64url');
      const hash = await bcrypt.hash(initialPassword, 12);
      
      // Menggunakan ON CONFLICT DO NOTHING (Pengganti INSERT OR IGNORE pada SQLite)
      await pool.query(`INSERT INTO users (id, username, password, role, force_reset) 
                        VALUES ($1, $2, $3, $4, $5) ON CONFLICT (username) DO NOTHING`,
        [crypto.randomUUID(), 'admin', hash, 'administrator', 1]);
      
      console.log('================================================================');
      console.log(' Akun administrator awal dibuat.');
      console.log(' Username : admin');
      console.log(' Password : ' + initialPassword);
      console.log(' Password ini hanya ditampilkan SEKALI. Segera login dan ganti.');
      console.log('================================================================');
    }
  } catch (err) {
    console.error('Terjadi kesalahan saat inisialisasi tabel:', err.message);
  }
}
initDb();

async function logAudit(req, aksi, target, detail) {
  try {
    await pool.query(`INSERT INTO audit_log (id, "userId", username, aksi, target, detail, ts) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [crypto.randomUUID(), req.session.userId || null, req.session.username || null, aksi, target || null, detail || null, Date.now()]);
  } catch (err) {
    console.error('Gagal mencatat audit log:', err.message);
  }
}

/* ============================= AUTHENTICATION MIDDLEWARE ============================= */
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  return res.status(401).json({ message: "Akses ditolak. Silakan login terlebih dahulu." });
}

function isAdministrator(req, res, next) {
  if (req.session && req.session.role === 'administrator') {
    return next();
  }
  return res.status(403).json({ message: "Akses dilarang. Hanya untuk Administrator." });
}

function isAllowedToMutate(req, res, next) {
  if (req.session && (req.session.role === 'administrator' || req.session.role === 'operator')) {
    return next();
  }
  return res.status(403).json({ message: "Akses dilarang. Viewer hanya memiliki hak baca data." });
}

// ================== FIX #9: Helper validasi input ==================
function isNonEmptyString(v, maxLen = 150) {
  return typeof v === 'string' && v.trim().length > 0 && v.trim().length <= maxLen;
}
function isPositiveNumber(v) {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0;
}
function isValidMonth(v) {
  const n = Number(v);
  return Number.isInteger(n) && n >= 0 && n <= 11;
}
function isValidYear(v) {
  const n = Number(v);
  return Number.isInteger(n) && n >= 2000 && n <= 2100;
}

/* ============================= API ENDPOINTS ============================= */

app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  console.log(`[login] percobaan login untuk username: "${username}"`);
  if (!isNonEmptyString(username, 100) || typeof password !== 'string' || password.length === 0) {
    return res.status(400).json({ message: "Username dan password wajib diisi." });
  }

  try {
    const result = await pool.query(`SELECT * FROM users WHERE username = $1`, [username.trim()]);
    const user = result.rows[0];

    if (!user) {
      console.log(`[login] username "${username}" tidak ditemukan di database.`);
      return res.status(401).json({ message: "Nama pengguna atau kata sandi salah." });
    }

    const match = await bcrypt.compare(password, user.password);
    
    if (!match) {
      console.log(`[login] password salah untuk username "${username}".`);
      return res.status(401).json({ message: "Nama pengguna atau kata sandi salah." });
    }

    console.log(`[login] password cocok untuk user "${user.username}", membuat sesi baru...`);

    let responded = false;
    const safetyTimeout = setTimeout(() => {
      if (responded) return;
      responded = true;
      console.error(`[login] TIMEOUT: session.regenerate() tidak merespons dalam 5 detik untuk user "${user.username}".`);
      res.status(500).json({ message: "Server terlalu lama membuat sesi. Coba lagi, atau cek log server." });
    }, 5000);

    req.session.regenerate((err) => {
      if (responded) return;
      clearTimeout(safetyTimeout);
      responded = true;

      if (err) {
        console.error('[login] session.regenerate() gagal:', err);
        return res.status(500).json({ message: "Gagal membuat sesi." });
      }

      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.role = user.role;

      logAudit(req, 'LOGIN', user.id, null);
      console.log(`[login] sukses, sesi dibuat untuk user "${user.username}" (role: ${user.role}).`);

      return res.json({
        id: user.id,
        username: user.username,
        role: user.role,
        forceReset: !!user.force_reset
      });
    });
  } catch (err) {
    console.error('[login] query database error:', err.message);
    return res.status(500).json({ message: "Terjadi kesalahan sistem saat memverifikasi kredensial." });
  }
});

app.post('/api/logout', isAuthenticated, (req, res) => {
  logAudit(req, 'LOGOUT', req.session.userId, null);
  req.session.destroy(err => {
    if (err) return res.status(500).json({ message: "Gagal log out." });
    res.clearCookie('connect.sid');
    return res.json({ message: "Berhasil keluar." });
  });
});

app.get('/api/data', isAuthenticated, async (req, res) => {
  const dataOut = {};
  dataOut.currentUser = {
    id: req.session.userId,
    username: req.session.username,
    role: req.session.role
  };

  try {
    const wargaRes = await pool.query(`SELECT id, nama, "nomorRumah", "jenisIuran" FROM warga`);
    dataOut.warga = wargaRes.rows;

    const pemRes = await pool.query(`SELECT * FROM pemasukan`);
    dataOut.pemasukan = pemRes.rows;

    const pengRes = await pool.query(`SELECT * FROM pengeluaran`);
    dataOut.pengeluaran = pengRes.rows;

    let userQuery = `SELECT id, username, '••••••••' as password, role FROM users`;
    let queryParams = [];
    if (req.session.role === 'viewer') {
      userQuery += ` WHERE id = $1`;
      queryParams.push(req.session.userId);
    }

    const userRes = await pool.query(userQuery, queryParams);
    dataOut.users = userRes.rows;

    res.json(dataOut);
  } catch (err) {
    console.error('[api/data] error:', err.message);
    res.status(500).json({ message: "Terjadi kesalahan saat mengambil data." });
  }
});

app.post('/api/warga', isAuthenticated, isAllowedToMutate, async (req, res) => {
  const { nama, nomorRumah, jenisIuran } = req.body;
  if (!isNonEmptyString(nama, 100) || !isNonEmptyString(nomorRumah, 30) || !isPositiveNumber(jenisIuran)) {
    return res.status(400).json({ message: "Data tidak lengkap atau tidak valid." });
  }

  const id = crypto.randomUUID();
  try {
    await pool.query(`INSERT INTO warga (id, nama, "nomorRumah", "jenisIuran") VALUES ($1, $2, $3, $4)`,
      [id, nama.trim(), nomorRumah.trim(), Number(jenisIuran)]);
    logAudit(req, 'CREATE_WARGA', id, nama.trim());
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Gagal menyimpan data." });
  }
});

app.put('/api/warga/:id', isAuthenticated, isAllowedToMutate, async (req, res) => {
  const { nama, nomorRumah, jenisIuran } = req.body;
  if (!isNonEmptyString(nama, 100) || !isNonEmptyString(nomorRumah, 30) || !isPositiveNumber(jenisIuran)) {
    return res.status(400).json({ message: "Data tidak lengkap atau tidak valid." });
  }

  try {
    await pool.query(`UPDATE warga SET nama = $1, "nomorRumah" = $2, "jenisIuran" = $3 WHERE id = $4`,
      [nama.trim(), nomorRumah.trim(), Number(jenisIuran), req.params.id]);
    logAudit(req, 'UPDATE_WARGA', req.params.id, nama.trim());
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Gagal memperbarui data." });
  }
});

app.delete('/api/warga/:id', isAuthenticated, isAllowedToMutate, async (req, res) => {
  try {
    await pool.query(`DELETE FROM warga WHERE id = $1`, [req.params.id]);
    logAudit(req, 'DELETE_WARGA', req.params.id, null);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: "Gagal menghapus data." });
  }
});

app.post('/api/pemasukan', isAuthenticated, isAllowedToMutate, async (req, res) => {
  const { wargaId, namaWarga, nomorRumah, bulan, tahun, jumlah, tanggal, ts, tipe } = req.body;
  if (!isNonEmptyString(namaWarga, 100) || !isValidMonth(bulan) || !isValidYear(tahun) || !isPositiveNumber(jumlah)) {
    return res.status(400).json({ message: "Data transaksi tidak valid." });
  }

  const id = crypto.randomUUID();
  try {
    await pool.query(`INSERT INTO pemasukan (id, "wargaId", "namaWarga", "nomorRumah", bulan, tahun, jumlah, tanggal, ts, tipe) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [id, wargaId || null, namaWarga.trim(), nomorRumah || '', Number(bulan), Number(tahun), Number(jumlah), tanggal, ts || Date.now(), tipe || 'iuran']);
    logAudit(req, 'CREATE_PEMASUKAN', id, namaWarga.trim());
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Gagal mencatat transaksi masuk." });
  }
});

app.delete('/api/pemasukan/:id', isAuthenticated, isAllowedToMutate, async (req, res) => {
  try {
    await pool.query(`DELETE FROM pemasukan WHERE id = $1`, [req.params.id]);
    logAudit(req, 'DELETE_PEMASUKAN', req.params.id, null);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: "Gagal menghapus transaksi." });
  }
});

app.post('/api/pengeluaran', isAuthenticated, isAllowedToMutate, async (req, res) => {
  const { keterangan, jumlah, tanggal, ts } = req.body;
  if (!isNonEmptyString(keterangan, 200) || !isPositiveNumber(jumlah)) {
    return res.status(400).json({ message: "Data transaksi tidak valid." });
  }

  const id = crypto.randomUUID();
  try {
    await pool.query(`INSERT INTO pengeluaran (id, keterangan, jumlah, tanggal, ts) VALUES ($1, $2, $3, $4, $5)`,
      [id, keterangan.trim(), Number(jumlah), tanggal, ts || Date.now()]);
    logAudit(req, 'CREATE_PENGELUARAN', id, keterangan.trim());
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: "Gagal mencatat transaksi keluar." });
  }
});

app.delete('/api/pengeluaran/:id', isAuthenticated, isAllowedToMutate, async (req, res) => {
  try {
    await pool.query(`DELETE FROM pengeluaran WHERE id = $1`, [req.params.id]);
    logAudit(req, 'DELETE_PENGELUARAN', req.params.id, null);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: "Gagal menghapus transaksi." });
  }
});

const VALID_ROLES = ['administrator', 'operator', 'viewer'];

app.post('/api/users', isAuthenticated, isAdministrator, async (req, res) => {
  const { username, password, role } = req.body;
  if (!isNonEmptyString(username, 50) || typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ message: "Username wajib diisi dan password minimal 8 karakter." });
  }
  const finalRole = VALID_ROLES.includes(role) ? role : 'operator';

  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    const id = crypto.randomUUID();
    await pool.query(`INSERT INTO users (id, username, password, role, force_reset) VALUES ($1, $2, $3, $4, 0)`,
      [id, username.trim(), hashedPassword, finalRole]);
      
    logAudit(req, 'CREATE_USER', id, username.trim() + ' (' + finalRole + ')');
    res.json({ success: true });
  } catch (err) {
    // Error code 23505 adalah unique_violation di PostgreSQL
    if (err.code === '23505') {
        return res.status(400).json({ message: "Username sudah terpakai." });
    }
    res.status(500).json({ message: "Terjadi kesalahan sistem." });
  }
});

// ================== FIX #10: PUT /api/users/:id diperketat ==================
app.put('/api/users/:id', isAuthenticated, async (req, res) => {
  const { password, role, username, currentPassword } = req.body;
  const isAdmin = req.session.role === 'administrator';
  const isSelf = req.session.userId === req.params.id;

  if (!isAdmin && !isSelf) {
    return res.status(403).json({ message: "Akses dilarang. Anda hanya bisa mengubah data milik sendiri." });
  }

  try {
    const result = await pool.query(`SELECT username, role, password as "oldPassword" FROM users WHERE id = $1`, [req.params.id]);
    const row = result.rows[0];
    
    if (!row) return res.status(404).json({ message: "User tidak ditemukan." });

    if (password && password.length > 0 && password.length < 8) {
      return res.status(400).json({ message: "Password baru minimal 8 karakter." });
    }

    if (isSelf && !isAdmin && password) {
      const match = await bcrypt.compare(currentPassword || '', row.oldPassword);
      if (!match) return res.status(401).json({ message: "Password saat ini salah." });
    }

    const finalPassword = password ? await bcrypt.hash(password, 12) : row.oldPassword;

    if (row.username === 'admin') {
      await pool.query(`UPDATE users SET password = $1, force_reset = 0 WHERE id = $2`, [finalPassword, req.params.id]);
      logAudit(req, 'UPDATE_USER_PASSWORD', req.params.id, 'admin');
      return res.json({ success: true });
    } else {
      const targetRole = isAdmin ? (VALID_ROLES.includes(role) ? role : row.role) : row.role;
      const targetUsername = (isAdmin && isNonEmptyString(username, 50)) ? username.trim() : row.username;

      try {
        await pool.query(`UPDATE users SET password = $1, role = $2, username = $3, force_reset = 0 WHERE id = $4`,
          [finalPassword, targetRole, targetUsername, req.params.id]);
        logAudit(req, 'UPDATE_USER', req.params.id, targetUsername + ' (' + targetRole + ')');
        return res.json({ success: true });
      } catch (updateErr) {
        if (updateErr.code === '23505') {
            return res.status(400).json({ message: "Username sudah terpakai." });
        }
        throw updateErr;
      }
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Terjadi kesalahan sistem." });
  }
});

app.delete('/api/users/:id', isAuthenticated, isAdministrator, async (req, res) => {
  try {
    const result = await pool.query(`SELECT username FROM users WHERE id = $1`, [req.params.id]);
    const row = result.rows[0];
    
    if (!row) return res.status(404).json({ message: "User tidak ditemukan." });

    if (row.username === 'admin') {
      return res.status(403).json({ message: "Akun admin utama tidak boleh dihapus!" });
    }

    await pool.query(`DELETE FROM users WHERE id = $1`, [req.params.id]);
    logAudit(req, 'DELETE_USER', req.params.id, row.username);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: "Gagal menghapus data user." });
  }
});

app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
  if (IS_PROD) {
    console.log('NODE_ENV=production aktif -> cookie sesi diset "secure" (hanya tersimpan lewat HTTPS).');
    console.log('Jika kamu mengakses aplikasi ini lewat http:// (bukan https://), login akan TAMPAK sukses');
    console.log('di log tapi cookie sesi tidak akan tersimpan di browser, sehingga panel admin tetap terkunci.');
    console.log('-> Untuk testing lokal tanpa HTTPS, set NODE_ENV=development di .env.');
  }
});