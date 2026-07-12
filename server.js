// Memuat variabel dari file .env (jika ada) ke process.env.
// Tanpa ini, Node.js TIDAK akan pernah membaca isi file .env secara otomatis.
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

// ================== FIX #1: SESSION_SECRET wajib diset via environment ==================
// Tidak ada lagi fallback hardcoded. Jika lupa diset, aplikasi sengaja gagal start
// daripada berjalan dengan secret yang bisa ditebak/diketahui publik.
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
  console.error('FATAL: environment variable SESSION_SECRET belum diset. Set nilai acak yang panjang, contoh:');
  console.error('  export SESSION_SECRET=$(node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))")');
  process.exit(1);
}

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
            // FIX #2: connectSrc tidak lagi wildcard "*". Hanya mengizinkan
            // koneksi fetch/XHR ke origin sendiri, mempersempit dampak jika
            // suatu saat ada celah XSS (mencegah exfiltrasi data ke domain lain).
            connectSrc: ["'self'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            frameAncestors: ["'self'"],
        },
    },
    // FIX #3: header isolasi cross-origin dikembalikan ke default helmet
    // (tidak dimatikan) karena tidak ada kebutuhan embed lintas origin di app ini.
}));

// 2. Parsing Data Middleware
app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: true, limit: '200kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ================== FIX #4: Session store persisten (bukan MemoryStore) ==================
// MemoryStore bawaan express-session eksplisit "not designed for production" —
// rawan bocor memori dan sesi hilang tiap restart server. Gunakan SQLite store
// yang konsisten dengan database yang sudah dipakai aplikasi ini.
app.use(session({
    store: new SQLiteStore({ db: 'sessions.db', dir: 'app/data' }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        // FIX #5: cookie sesi wajib "secure" di production (hanya dikirim lewat HTTPS),
        // mencegah pencurian session cookie lewat sniffing di jaringan HTTP biasa.
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
// Sebelumnya hanya /api/login yang dibatasi. Endpoint lain rawan disalahgunakan
// (spam request, DoS ringan) oleh siapapun yang sudah memiliki sesi (termasuk viewer).
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Terlalu banyak permintaan, silakan coba lagi beberapa saat lagi." }
});
app.use('/api/', apiLimiter);

/* ============================= DATABASE SETUP (SQLITE) ============================= */
const db = new sqlite3.Database('/app/data/database.db', (err) => {
  if (err) console.error(err.message);
  console.log('Terhubung ke database SQLite fisik (database.db).');
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS warga (
    id TEXT PRIMARY KEY, nama TEXT, nomorRumah TEXT, jenisIuran INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS pemasukan (
    id TEXT PRIMARY KEY, wargaId TEXT, namaWarga TEXT, nomorRumah TEXT,
    bulan INTEGER, tahun INTEGER, jumlah INTEGER, tanggal TEXT, ts INTEGER, tipe TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS pengeluaran (
    id TEXT PRIMARY KEY, keterangan TEXT, jumlah INTEGER, tanggal TEXT, ts INTEGER
  )`);
  // FIX #7: audit log untuk akuntabilitas — siapa melakukan aksi apa dan kapan.
  db.run(`CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY, userId TEXT, username TEXT, aksi TEXT, target TEXT, detail TEXT, ts INTEGER
  )`);

  // Migrasi ringan: tambah kolom force_reset bila belum ada (aman dipanggil berulang,
  // error "duplicate column" akan diabaikan).
  db.run(`ALTER TABLE users ADD COLUMN force_reset INTEGER DEFAULT 0`, () => {});

  // FIX #8: password default admin tidak lagi hardcoded "admin". Digenerate acak
  // sekali saat pertama kali seed, dicetak SATU KALI ke log server, dan user
  // dipaksa mengganti password pada login pertama (force_reset = 1).
  db.get(`SELECT id FROM users WHERE username = ?`, ['admin'], (err, row) => {
    if (err || row) return; // sudah ada, tidak perlu seed ulang
    const initialPassword = crypto.randomBytes(9).toString('base64url');
    bcrypt.hash(initialPassword, 12, (err, hash) => {
      if (err) return;
      db.run(`INSERT OR IGNORE INTO users (id, username, password, role, force_reset) VALUES (?, ?, ?, ?, ?)`,
        [crypto.randomUUID(), 'admin', hash, 'administrator', 1]);
      console.log('================================================================');
      console.log(' Akun administrator awal dibuat.');
      console.log(' Username : admin');
      console.log(' Password : ' + initialPassword);
      console.log(' Password ini hanya ditampilkan SEKALI. Segera login dan ganti.');
      console.log('================================================================');
    });
  });
});

function logAudit(req, aksi, target, detail) {
  db.run(`INSERT INTO audit_log (id, userId, username, aksi, target, detail, ts) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [crypto.randomUUID(), req.session.userId || null, req.session.username || null, aksi, target || null, detail || null, Date.now()]);
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

app.post('/api/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  console.log(`[login] percobaan login untuk username: "${username}"`);
  if (!isNonEmptyString(username, 100) || typeof password !== 'string' || password.length === 0) {
    return res.status(400).json({ message: "Username dan password wajib diisi." });
  }

  db.get(`SELECT * FROM users WHERE username = ?`, [username.trim()], async (err, user) => {
    if (err) {
      console.error('[login] query database error:', err.message);
      return res.status(401).json({ message: "Nama pengguna atau kata sandi salah." });
    }
    if (!user) {
      console.log(`[login] username "${username}" tidak ditemukan di database.`);
      return res.status(401).json({ message: "Nama pengguna atau kata sandi salah." });
    }

    let match = false;
    try {
      match = await bcrypt.compare(password, user.password);
    } catch (compareErr) {
      // Menangkap kasus data password rusak/kosong di database agar tidak
      // membuat request menggantung tanpa respons sama sekali.
      console.error('Gagal membandingkan password untuk user "' + user.username + '":', compareErr.message);
      return res.status(500).json({ message: "Terjadi kesalahan sistem saat memverifikasi kredensial." });
    }
    if (!match) {
      console.log(`[login] password salah untuk username "${username}".`);
      return res.status(401).json({ message: "Nama pengguna atau kata sandi salah." });
    }

    // Regenerasi session id saat login untuk mencegah session fixation.
    console.log(`[login] password cocok untuk user "${user.username}", membuat sesi baru...`);

    // Pengaman: jika store sesi (SQLite) macet/lambat merespons regenerate,
    // jangan biarkan request menggantung selamanya tanpa respons ke frontend.
    let responded = false;
    const safetyTimeout = setTimeout(() => {
      if (responded) return;
      responded = true;
      console.error(`[login] TIMEOUT: session.regenerate() tidak merespons dalam 5 detik untuk user "${user.username}". Kemungkinan ada masalah pada session store (sessions.db).`);
      res.status(500).json({ message: "Server terlalu lama membuat sesi. Coba lagi, atau cek log server (kemungkinan masalah pada sessions.db)." });
    }, 5000);

    req.session.regenerate((err) => {
      if (responded) return; // safety timeout sudah lebih dulu merespons
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
  });
});

app.post('/api/logout', isAuthenticated, (req, res) => {
  logAudit(req, 'LOGOUT', req.session.userId, null);
  req.session.destroy(err => {
    if (err) return res.status(500).json({ message: "Gagal log out." });
    res.clearCookie('connect.sid');
    return res.json({ message: "Berhasil keluar." });
  });
});

app.get('/api/data', isAuthenticated, (req, res) => {
  const dataOut = {};
  // FIX (bug tambahan): sertakan identitas user yang sedang login di setiap
  // response /api/data, agar frontend tidak kehilangan status role saat halaman
  // di-refresh (sebelumnya currentUser hanya terisi saat login, hilang setelah reload).
  dataOut.currentUser = {
    id: req.session.userId,
    username: req.session.username,
    role: req.session.role
  };

  db.all(`SELECT id, nama, nomorRumah, jenisIuran FROM warga`, [], (err, wargaRows) => {
    dataOut.warga = wargaRows || [];
    db.all(`SELECT * FROM pemasukan`, [], (err, pemRows) => {
      dataOut.pemasukan = pemRows || [];
      db.all(`SELECT * FROM pengeluaran`, [], (err, pengRows) => {
        dataOut.pengeluaran = pengRows || [];

        let userQuery = `SELECT id, username, '••••••••' as password, role FROM users`;
        let queryParams = [];
        if (req.session.role === 'viewer') {
          userQuery += ` WHERE id = ?`;
          queryParams.push(req.session.userId);
        }

        db.all(userQuery, queryParams, (err, userRows) => {
          dataOut.users = userRows || [];
          res.json(dataOut);
        });
      });
    });
  });
});

app.post('/api/warga', isAuthenticated, isAllowedToMutate, (req, res) => {
  const { nama, nomorRumah, jenisIuran } = req.body;
  if (!isNonEmptyString(nama, 100) || !isNonEmptyString(nomorRumah, 30) || !isPositiveNumber(jenisIuran)) {
    return res.status(400).json({ message: "Data tidak lengkap atau tidak valid." });
  }

  const id = crypto.randomUUID();
  db.run(`INSERT INTO warga (id, nama, nomorRumah, jenisIuran) VALUES (?, ?, ?, ?)`,
    [id, nama.trim(), nomorRumah.trim(), Number(jenisIuran)], (err) => {
      if (err) return res.status(500).json({ message: "Gagal menyimpan data." });
      logAudit(req, 'CREATE_WARGA', id, nama.trim());
      res.json({ success: true });
    });
});

app.put('/api/warga/:id', isAuthenticated, isAllowedToMutate, (req, res) => {
  const { nama, nomorRumah, jenisIuran } = req.body;
  if (!isNonEmptyString(nama, 100) || !isNonEmptyString(nomorRumah, 30) || !isPositiveNumber(jenisIuran)) {
    return res.status(400).json({ message: "Data tidak lengkap atau tidak valid." });
  }

  db.run(`UPDATE warga SET nama = ?, nomorRumah = ?, jenisIuran = ? WHERE id = ?`,
    [nama.trim(), nomorRumah.trim(), Number(jenisIuran), req.params.id], (err) => {
      if (err) return res.status(500).json({ message: "Gagal memperbarui data." });
      logAudit(req, 'UPDATE_WARGA', req.params.id, nama.trim());
      res.json({ success: true });
    });
});

app.delete('/api/warga/:id', isAuthenticated, isAllowedToMutate, (req, res) => {
  db.run(`DELETE FROM warga WHERE id = ?`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: "Gagal menghapus data." });
    logAudit(req, 'DELETE_WARGA', req.params.id, null);
    res.json({ success: true });
  });
});

app.post('/api/pemasukan', isAuthenticated, isAllowedToMutate, (req, res) => {
  const { wargaId, namaWarga, nomorRumah, bulan, tahun, jumlah, tanggal, ts, tipe } = req.body;
  if (!isNonEmptyString(namaWarga, 100) || !isValidMonth(bulan) || !isValidYear(tahun) || !isPositiveNumber(jumlah)) {
    return res.status(400).json({ message: "Data transaksi tidak valid." });
  }

  const id = crypto.randomUUID();
  db.run(`INSERT INTO pemasukan (id, wargaId, namaWarga, nomorRumah, bulan, tahun, jumlah, tanggal, ts, tipe) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, wargaId || null, namaWarga.trim(), nomorRumah || '', Number(bulan), Number(tahun), Number(jumlah), tanggal, ts || Date.now(), tipe || 'iuran'], (err) => {
      if (err) return res.status(500).json({ message: "Gagal mencatat transaksi masuk." });
      logAudit(req, 'CREATE_PEMASUKAN', id, namaWarga.trim());
      res.json({ success: true });
    });
});

app.delete('/api/pemasukan/:id', isAuthenticated, isAllowedToMutate, (req, res) => {
  db.run(`DELETE FROM pemasukan WHERE id = ?`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: "Gagal menghapus transaksi." });
    logAudit(req, 'DELETE_PEMASUKAN', req.params.id, null);
    res.json({ success: true });
  });
});

app.post('/api/pengeluaran', isAuthenticated, isAllowedToMutate, (req, res) => {
  const { keterangan, jumlah, tanggal, ts } = req.body;
  if (!isNonEmptyString(keterangan, 200) || !isPositiveNumber(jumlah)) {
    return res.status(400).json({ message: "Data transaksi tidak valid." });
  }

  const id = crypto.randomUUID();
  db.run(`INSERT INTO pengeluaran (id, keterangan, jumlah, tanggal, ts) VALUES (?, ?, ?, ?, ?)`,
    [id, keterangan.trim(), Number(jumlah), tanggal, ts || Date.now()], (err) => {
      if (err) return res.status(500).json({ message: "Gagal mencatat transaksi keluar." });
      logAudit(req, 'CREATE_PENGELUARAN', id, keterangan.trim());
      res.json({ success: true });
    });
});

app.delete('/api/pengeluaran/:id', isAuthenticated, isAllowedToMutate, (req, res) => {
  db.run(`DELETE FROM pengeluaran WHERE id = ?`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: "Gagal menghapus transaksi." });
    logAudit(req, 'DELETE_PENGELUARAN', req.params.id, null);
    res.json({ success: true });
  });
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
    db.run(`INSERT INTO users (id, username, password, role, force_reset) VALUES (?, ?, ?, ?, 0)`,
      [id, username.trim(), hashedPassword, finalRole], (err) => {
        if (err) return res.status(400).json({ message: "Username sudah terpakai." });
        logAudit(req, 'CREATE_USER', id, username.trim() + ' (' + finalRole + ')');
        res.json({ success: true });
      });
  } catch {
    res.status(500).json({ message: "Terjadi kesalahan sistem." });
  }
});

// ================== FIX #10: PUT /api/users/:id diperketat ==================
// - User non-admin HANYA boleh mengubah akunnya sendiri, dan HANYA kolom password.
//   Role & username tidak bisa lagi diubah sendiri lewat body request (sebelumnya
//   nilai body diikuti begitu saja untuk permintaan non-admin terhadap akunnya sendiri).
// - Mengganti password milik sendiri WAJIB menyertakan currentPassword yang benar,
//   supaya sesi yang "kecolongan"/dibajak tidak otomatis bisa mengambil alih akun
//   dengan mengganti password tanpa mengetahui password lamanya.
app.put('/api/users/:id', isAuthenticated, async (req, res) => {
  const { password, role, username, currentPassword } = req.body;
  const isAdmin = req.session.role === 'administrator';
  const isSelf = req.session.userId === req.params.id;

  if (!isAdmin && !isSelf) {
    return res.status(403).json({ message: "Akses dilarang. Anda hanya bisa mengubah data milik sendiri." });
  }

  try {
    db.get(`SELECT username, role, password as oldPassword FROM users WHERE id = ?`, [req.params.id], async (err, row) => {
      if (!row) return res.status(404).json({ message: "User tidak ditemukan." });

      if (password && password.length > 0 && password.length < 8) {
        return res.status(400).json({ message: "Password baru minimal 8 karakter." });
      }

      // Verifikasi password lama wajib untuk self-service (non-admin mengubah akun sendiri).
      if (isSelf && !isAdmin && password) {
        const match = await bcrypt.compare(currentPassword || '', row.oldPassword);
        if (!match) return res.status(401).json({ message: "Password saat ini salah." });
      }

      const finalPassword = password ? await bcrypt.hash(password, 12) : row.oldPassword;

      if (row.username === 'admin') {
        // Akun admin utama: hanya password yang boleh berubah, role/username tetap.
        db.run(`UPDATE users SET password = ?, force_reset = 0 WHERE id = ?`, [finalPassword, req.params.id], (err) => {
          if (err) return res.status(500).json({ message: "Gagal memperbarui password admin utama." });
          logAudit(req, 'UPDATE_USER_PASSWORD', req.params.id, 'admin');
          return res.json({ success: true });
        });
      } else {
        // Non-admin (self-service) tidak boleh mengubah role atau username miliknya sendiri.
        const targetRole = isAdmin ? (VALID_ROLES.includes(role) ? role : row.role) : row.role;
        const targetUsername = (isAdmin && isNonEmptyString(username, 50)) ? username.trim() : row.username;

        db.run(`UPDATE users SET password = ?, role = ?, username = ?, force_reset = 0 WHERE id = ?`,
          [finalPassword, targetRole, targetUsername, req.params.id], (err) => {
          if (err) return res.status(500).json({ message: "Gagal memperbarui data user. Username mungkin sudah terpakai." });
          logAudit(req, 'UPDATE_USER', req.params.id, targetUsername + ' (' + targetRole + ')');
          return res.json({ success: true });
        });
      }
    });
  } catch {
    res.status(500).json({ message: "Terjadi kesalahan sistem." });
  }
});

app.delete('/api/users/:id', isAuthenticated, isAdministrator, (req, res) => {
  db.get(`SELECT username FROM users WHERE id = ?`, [req.params.id], (err, row) => {
    if (!row) return res.status(404).json({ message: "User tidak ditemukan." });

    // Keamanan lapis dua: cegah penghapusan lewat API langsung
    if (row.username === 'admin') {
      return res.status(403).json({ message: "Akun admin utama tidak boleh dihapus!" });
    }

    db.run(`DELETE FROM users WHERE id = ?`, [req.params.id], (err) => {
      if (err) return res.status(500).json({ message: "Gagal menghapus data user." });
      logAudit(req, 'DELETE_USER', req.params.id, row.username);
      res.json({ success: true });
    });
  });
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