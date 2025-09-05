const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Database SQLite
const db = new sqlite3.Database('./keys.db', (err) => {
    if (err) {
        console.error('Lỗi kết nối database:', err);
    } else {
        console.log('Kết nối SQLite thành công');
    }
});

// Tạo bảng keys nếu chưa tồn tại
db.run(`CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    ip TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    used BOOLEAN DEFAULT FALSE
)`);

// Hàm tạo key dạng key-xxxxxxxxxxxxxxxxxx (18 ký tự)
function generateKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let randomStr = '';
    for (let i = 0; i < 18; i++) {
        randomStr += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return `key-${randomStr}`;
}

// API tạo key mới
app.post('/get-key', (req, res) => {
    const userIp = req.ip || req.connection.remoteAddress;
    const newKey = generateKey();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 giờ

    // Kiểm tra IP đã có key còn hạn chưa
    db.get(
        'SELECT * FROM keys WHERE ip = ? AND expires_at > datetime("now") AND used = FALSE',
        [userIp],
        (err, row) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: 'Lỗi database'
                });
            }

            if (row) {
                return res.json({
                    success: true,
                    key: row.key,
                    expires: row.expires_at,
                    message: 'Bạn đã có key chưa hết hạn'
                });
            }

            // Tạo key mới
            db.run(
                'INSERT INTO keys (key, ip, expires_at) VALUES (?, ?, ?)',
                [newKey, userIp, expiresAt.toISOString()],
                function (err) {
                    if (err) {
                        return res.status(500).json({
                            success: false,
                            message: 'Lỗi khi tạo key'
                        });
                    }

                    res.json({
                        success: true,
                        key: newKey,
                        expires: expiresAt.toISOString()
                    });
                }
            );
        }
    );
});

// API xác thực key
app.get('/verify-key', (req, res) => {
    const { key } = req.query;

    if (!key) {
        return res.json({ valid: false, reason: 'Thiếu key' });
    }

    db.get(
        'SELECT * FROM keys WHERE key = ? AND expires_at > datetime("now")',
        [key],
        (err, row) => {
            if (err) {
                return res.status(500).json({ valid: false, reason: 'Lỗi server' });
            }

            if (!row) {
                return res.json({ valid: false, reason: 'Key không hợp lệ hoặc đã hết hạn' });
            }

            if (row.used) {
                return res.json({ valid: false, reason: 'Key đã được sử dụng' });
            }

            // Đánh dấu key đã sử dụng
            db.run(
                'UPDATE keys SET used = TRUE WHERE key = ?',
                [key]
            );

            res.json({ valid: true, expires: row.expires_at });
        }
    );
});

// Khởi động server
app.listen(PORT, () => {
    console.log(`✅ Server đang chạy tại http://localhost:${PORT}`);
});
