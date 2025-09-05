const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// SQLite DB
const db = new sqlite3.Database('./keys.db', (err) => {
    if (err) console.error('❌ Lỗi DB:', err);
    else console.log('✅ Kết nối SQLite thành công');
});

// Tạo bảng keys
db.run(`CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    ip TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    used BOOLEAN DEFAULT FALSE
)`);

// 📌 API tạo key mới
app.post('/get-key', (req, res) => {
    const userIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const newKey = "key-" + uuidv4().replace(/-/g, '').substring(0, 18);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h

    db.get(
        'SELECT * FROM keys WHERE ip = ? AND expires_at > datetime("now") AND used = FALSE',
        [userIp],
        (err, row) => {
            if (err) return res.status(500).json({ success: false, message: 'Lỗi DB' });

            if (row) {
                return res.json({
                    success: true,
                    key: row.key,
                    expires: row.expires_at,
                    message: 'Bạn đã có key chưa hết hạn'
                });
            }

            db.run(
                'INSERT INTO keys (key, ip, expires_at) VALUES (?, ?, ?)',
                [newKey, userIp, expiresAt.toISOString()],
                function (err) {
                    if (err) return res.status(500).json({ success: false, message: 'Lỗi khi tạo key' });

                    res.json({
                        success: true,
                        key: newKey,
                        expires: expiresAt.toISOString(),
                        message: 'Tạo key thành công'
                    });
                }
            );
        }
    );
});

// 📌 API kiểm tra key (Luau gọi cái này trước)
app.get('/verify-key', (req, res) => {
    const { key } = req.query;
    if (!key) return res.json({ valid: false, reason: 'Thiếu key' });

    db.get(
        'SELECT * FROM keys WHERE key = ? AND expires_at > datetime("now")',
        [key],
        (err, row) => {
            if (err) return res.status(500).json({ valid: false, reason: 'Lỗi server' });
            if (!row) return res.json({ valid: false, reason: 'Key không hợp lệ hoặc đã hết hạn' });
            if (row.used) return res.json({ valid: false, reason: 'Key đã được sử dụng' });

            res.json({ valid: true, expires: row.expires_at });
        }
    );
});

// 📌 API consume key (đánh dấu key đã dùng khi script active)
app.post('/consume-key', (req, res) => {
    const { key } = req.body;
    if (!key) return res.json({ success: false, reason: 'Thiếu key' });

    db.get(
        'SELECT * FROM keys WHERE key = ?',
        [key],
        (err, row) => {
            if (err) return res.status(500).json({ success: false, reason: 'Lỗi DB' });
            if (!row) return res.json({ success: false, reason: 'Key không tồn tại' });
            if (row.used) return res.json({ success: false, reason: 'Key đã được sử dụng' });

            db.run('UPDATE keys SET used = TRUE WHERE key = ?', [key], function (err) {
                if (err) return res.status(500).json({ success: false, reason: 'Không update được' });

                res.json({ success: true, message: 'Key đã được kích hoạt' });
            });
        }
    );
});

// 📌 API test server
app.get('/status', (req, res) => {
    res.json({ server: 'running', time: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server đang chạy tại cổng ${PORT}`);
});
