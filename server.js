// server.js
// Full-featured key system (Express + SQLite) ready for Render.
// - Keeps original endpoints: /get-key, /verify-key, /key-info, /check-time-left, /health, /
// - Adds /request-token (create token + redirect), token validation in /get-key
// - Adds /admin/cleanup
// Config via env: LINKVERTISE_BASE, TOKEN_TTL_MS, KEY_TTL_MS, COOLDOWN_MS

const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Config (override with Render env vars if desired)
const LINKVERTISE_BASE = process.env.LINKVERTISE_BASE || ''; // e.g. "https://linkvertise.com/xxxxx" or empty to return direct URL
const TOKEN_TTL_MS = +(process.env.TOKEN_TTL_MS || 5 * 60 * 1000); // token TTL default 5 minutes
const KEY_TTL_MS = +(process.env.KEY_TTL_MS || 24 * 60 * 60 * 1000); // key TTL default 24 hours
const COOLDOWN_MS = +(process.env.COOLDOWN_MS || 60 * 60 * 1000); // 1 hour cooldown

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // serve frontend from /public

// DB file (in project root)
const DB_FILE = path.join(__dirname, 'keys.db');
const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) console.error('Lỗi kết nối database:', err);
  else console.log('Kết nối SQLite thành công:', DB_FILE);
});

// Create tables if not exists (keeps original schema and adds tokens)
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    hwid TEXT,
    user_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    used INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hwid TEXT NOT NULL,
    last_request_time DATETIME NOT NULL,
    request_count INTEGER DEFAULT 1
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    hwid TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL
  )`);
});

// Utility functions
function generateRandomKey(length = 5) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `key-${result}`;
}
function nowISO() { return new Date().toISOString(); }
function nowMs() { return Date.now(); }

// ----------------- Endpoints -----------------

// Root: serve index.html if exists (express.static covers it), but keep JSON for API-check
app.get('/', (req, res) => {
  // If you want to return JSON for API root, uncomment below and remove static serve behavior.
  // res.json({ message: 'Key System API đang hoạt động', endpoints: {...} });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Health
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: nowISO(), service: 'Key System API' });
});

// ---------------- request-token ----------------
// Create a one-time token tied to HWID and return redirect link (Linkvertise or direct return)
app.post('/request-token', (req, res) => {
  try {
    const { hwid } = req.body;
    if (!hwid) return res.status(400).json({ success: false, message: 'Thiếu HWID' });

    const token = uuidv4();
    const createdAt = nowISO();
    const expiresAt = new Date(nowMs() + TOKEN_TTL_MS).toISOString();

    db.run('INSERT INTO tokens (token, hwid, created_at, expires_at) VALUES (?, ?, ?, ?)',
      [token, hwid, createdAt, expiresAt], function(err) {
        if (err) {
          console.error('Insert token error:', err);
          return res.status(500).json({ success: false, message: 'Lỗi khi tạo token' });
        }

        // Build return URL (Linkvertise should redirect back to this)
        const origin = req.get('origin') || `${req.protocol}://${req.get('host')}`;
        const returnUrl = `${origin}/?token=${encodeURIComponent(token)}&hwid=${encodeURIComponent(hwid)}`;

        let redirect;
        if (LINKVERTISE_BASE && LINKVERTISE_BASE.length) {
          // Many Linkvertise configs accept params and forward them; adapt if your Linkvertise needs `target=` param.
          // If LINKVERTISE_BASE requires a 'target' param, set LINKVERTISE_BASE to "https://linkvertise.com/xxxxx?target="
          // then the redirect below will become LINKVERTISE_BASE + encodeURIComponent(returnUrl)
          // Here we append token & hwid so Linkvertise may forward them when redirecting to returnUrl.
          redirect = `${LINKVERTISE_BASE}?token=${encodeURIComponent(token)}&hwid=${encodeURIComponent(hwid)}`;
        } else {
          redirect = returnUrl; // direct (no Linkvertise)
        }

        return res.json({ success: true, token, redirect, message: 'Token đã được tạo' });
      });

  } catch (e) {
    console.error('Error in /request-token:', e);
    res.status(500).json({ success: false, message: 'Lỗi server nội bộ' });
  }
});

// ---------------- get-key ----------------
// Supports both old flow (no token) and token flow (token validation).
app.post('/get-key', (req, res) => {
  try {
    const { hwid, token } = req.body;
    if (!hwid) return res.status(400).json({ success: false, message: 'Thiếu HWID' });

    const now = new Date();

    // Helper to run existing key creation flow (enforces cooldown)
    const createKeyFlow = () => {
      db.get('SELECT * FROM requests WHERE hwid = ?', [hwid], (err, row) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ success: false, message: 'Lỗi server' });
        }

        if (row) {
          const lastRequestTime = new Date(row.last_request_time);
          const timeDiff = now - lastRequestTime;
          const hoursDiff = timeDiff / (1000 * 60 * 60);

          if (hoursDiff < 1) {
            const timeLeft = 1 - hoursDiff;
            const hoursLeft = Math.floor(timeLeft);
            const minutesLeft = Math.floor((timeLeft - hoursLeft) * 60);

            return res.status(429).json({
              success: false,
              message: `Bạn phải chờ ${hoursLeft} giờ ${minutesLeft} phút nữa để lấy key mới`,
              time_left: timeLeft
            });
          }

          db.run('UPDATE requests SET last_request_time = ?, request_count = request_count + 1 WHERE hwid = ?',
            [now.toISOString(), hwid], (err) => {
              if (err) console.error('Update request error:', err);
            });
        } else {
          db.run('INSERT INTO requests (hwid, last_request_time) VALUES (?, ?)',
            [hwid, now.toISOString()], (err) => {
              if (err) console.error('Insert request error:', err);
            });
        }

        const newKey = generateRandomKey(5);
        const expiresAt = new Date(nowMs() + KEY_TTL_MS).toISOString();

        db.run('INSERT INTO keys (key, hwid, expires_at) VALUES (?, ?, ?)',
          [newKey, hwid, expiresAt], function(err) {
            if (err) {
              console.error('Insert key error:', err);
              return res.status(500).json({ success: false, message: 'Lỗi khi tạo key' });
            }

            return res.json({ success: true, key: newKey, expires: expiresAt, message: 'Key đã được tạo thành công' });
          });
      });
    };

    // If token is provided, validate it first
    if (token) {
      db.get('SELECT * FROM tokens WHERE token = ?', [token], (err, tokRow) => {
        if (err) {
          console.error('Token DB error:', err);
          return res.status(500).json({ success: false, message: 'Lỗi server' });
        }
        if (!tokRow) return res.status(403).json({ success: false, message: 'Token không hợp lệ' });

        // validate HWID
        if (tokRow.hwid !== hwid) return res.status(403).json({ success: false, message: 'Token không khớp HWID' });

        // validate expiry
        if (new Date(tokRow.expires_at) < now) {
          // delete token
          db.run('DELETE FROM tokens WHERE token = ?', [token], (e) => { if (e) console.error('Delete expired token err', e); });
          return res.status(403).json({ success: false, message: 'Token đã hết hạn' });
        }

        // token ok -> create key
        createKeyFlow();

        // delete token single-use
        db.run('DELETE FROM tokens WHERE token = ?', [token], (e) => { if (e) console.error('Delete token err:', e); });

      });
    } else {
      // old direct flow (unchanged)
      createKeyFlow();
    }

  } catch (error) {
    console.error('Error in /get-key:', error);
    res.status(500).json({ success: false, message: 'Lỗi server nội bộ' });
  }
});

// ---------------- verify-key ----------------
app.post('/verify-key', (req, res) => {
  try {
    const { key, user_id } = req.body;
    if (!key) return res.json({ valid: false, reason: 'Thiếu key' });
    if (!user_id) return res.json({ valid: false, reason: 'Thiếu user_id' });

    db.get('SELECT * FROM keys WHERE key = ?', [key], (err, row) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ valid: false, reason: 'Lỗi server' });
      }
      if (!row) return res.json({ valid: false, reason: 'Key không tồn tại' });

      const now = new Date();
      const expiresAt = new Date(row.expires_at);
      if (now > expiresAt) return res.json({ valid: false, reason: 'Key đã hết hạn' });

      if (row.used && row.user_id && row.user_id !== user_id) {
        return res.json({ valid: false, reason: 'Key đã được sử dụng bởi user khác' });
      }

      if (!row.used) {
        db.run('UPDATE keys SET used = 1, user_id = ? WHERE key = ?', [user_id, key], (err2) => {
          if (err2) console.error('Failed to mark key used:', err2);
        });
      }

      return res.json({ valid: true, user_id: row.user_id || user_id, created_at: row.created_at, expires_at: row.expires_at });
    });
  } catch (e) {
    console.error('Error in /verify-key:', e);
    res.status(500).json({ valid: false, reason: 'Lỗi server nội bộ' });
  }
});

// ---------------- key-info ----------------
app.get('/key-info/:key', (req, res) => {
  const { key } = req.params;
  db.get('SELECT * FROM keys WHERE key = ?', [key], (err, row) => {
    if (err) return res.status(500).json({ error: 'Lỗi database' });
    if (!row) return res.json({ exists: false, message: 'Key không tồn tại' });
    return res.json({
      exists: true,
      key: row.key,
      user_id: row.user_id,
      hwid: row.hwid,
      created_at: row.created_at,
      expires_at: row.expires_at,
      used: row.used === 1,
      is_expired: new Date() > new Date(row.expires_at)
    });
  });
});

// ---------------- check-time-left ----------------
app.post('/check-time-left', (req, res) => {
  try {
    const { hwid } = req.body;
    if (!hwid) return res.status(400).json({ success: false, message: 'Thiếu HWID' });

    db.get('SELECT * FROM requests WHERE hwid = ?', [hwid], (err, row) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Lỗi server' });
      }
      if (!row) return res.json({ can_request: true, time_left: 0, message: 'Bạn có thể lấy key ngay bây giờ' });

      const lastRequestTime = new Date(row.last_request_time);
      const now = new Date();
      const timeDiff = now - lastRequestTime;
      const hoursDiff = timeDiff / (1000 * 60 * 60);
      if (hoursDiff >= 1) return res.json({ can_request: true, time_left: 0, message: 'Bạn có thể lấy key ngay bây giờ' });

      const timeLeft = 1 - hoursDiff;
      const hoursLeft = Math.floor(timeLeft);
      const minutesLeft = Math.floor((timeLeft - hoursLeft) * 60);
      return res.json({ can_request: false, time_left: timeLeft, message: `Bạn phải chờ ${hoursLeft} giờ ${minutesLeft} phút nữa để lấy key mới` });
    });
  } catch (err) {
    console.error('Error in /check-time-left:', err);
    res.status(500).json({ success: false, message: 'Lỗi server nội bộ' });
  }
});

// ---------------- admin cleanup ----------------
app.post('/admin/cleanup', (req, res) => {
  try {
    const nowIso = nowISO();
    db.run('DELETE FROM tokens WHERE expires_at < ?', [nowIso], function(err) {
      if (err) console.error('cleanup tokens err:', err);
      db.run('DELETE FROM keys WHERE expires_at < ?', [nowIso], function(err2) {
        if (err2) console.error('cleanup keys err:', err2);
        return res.json({ success: true, message: 'Cleanup done' });
      });
    });
  } catch (e) {
    console.error('Error admin cleanup:', e);
    res.status(500).json({ success: false, message: 'Lỗi server' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server đang chạy trên port ${PORT}`);
  console.log(`TOKEN_TTL_MS=${TOKEN_TTL_MS}, KEY_TTL_MS=${KEY_TTL_MS}, COOLDOWN_MS=${COOLDOWN_MS}`);
  if (LINKVERTISE_BASE) console.log(`LINKVERTISE_BASE is set: ${LINKVERTISE_BASE}`);
});
