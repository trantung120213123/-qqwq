const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Khởi tạo database
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
    user_id TEXT,
    ip TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    used BOOLEAN DEFAULT FALSE
)`);

// Hàm tạo key ngẫu nhiên 20 ký tự
function generateRandomKey(length = 20) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// API tạo key mới
app.post('/get-key', (req, res) => {
    const userIp = req.ip || req.connection.remoteAddress;
    const { user_id } = req.body;
    
    // Xác định identifier (ưu tiên user_id nếu có)
    const identifier = user_id || userIp;
    const identifierType = user_id ? 'user_id' : 'ip';
    
    const newKey = `key-${generateRandomKey(20)}`;
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 giờ
    
    // Kiểm tra xem identifier đã có key chưa hết hạn chưa
    const query = `SELECT * FROM keys WHERE ${identifierType} = ? AND expires_at > datetime("now") AND used = FALSE`;
    
    db.get(query, [identifier], (err, row) => {
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
                message: 'Bạn đã có key chưa sử dụng' 
            });
        }
        
        // Tạo key mới
        db.run(
            'INSERT INTO keys (key, user_id, ip, expires_at) VALUES (?, ?, ?, ?)',
            [newKey, user_id || null, user_id ? null : userIp, expiresAt.toISOString()],
            function(err) {
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
    });
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
            
            res.json({ valid: true });
        }
    );
});

// API lấy thông tin key theo user_id hoặc IP
app.get('/key-info', (req, res) => {
    const { user_id, ip } = req.query;
    
    if (!user_id && !ip) {
        return res.status(400).json({ error: 'Thiếu user_id hoặc ip' });
    }
    
    const query = user_id 
        ? 'SELECT * FROM keys WHERE user_id = ? ORDER BY created_at DESC LIMIT 1' 
        : 'SELECT * FROM keys WHERE ip = ? ORDER BY created_at DESC LIMIT 1';
    
    const param = user_id || ip;
    
    db.get(query, [param], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        if (!row) {
            return res.json({ exists: false });
        }
        
        res.json({
            exists: true,
            key: row.key,
            created_at: row.created_at,
            expires_at: row.expires_at,
            used: row.used === 1
        });
    });
});

// Khởi động server
app.listen(PORT, () => {
    console.log(`Server đang chạy trên port ${PORT}`);
});
