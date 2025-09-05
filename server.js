const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Khởi tạo database
const db = new sqlite3.Database(':memory:', (err) => {
    if (err) {
        console.error('Lỗi kết nối database:', err);
    } else {
        console.log('Kết nối SQLite trong memory thành công');
    }
});

// Tạo bảng keys
db.run(`CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    user_id TEXT,
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
    return `key-${result}`;
}

// API tạo key mới (không cần user_id)
app.post('/get-key', (req, res) => {
    try {
        const newKey = generateRandomKey(20);
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 giờ
        
        // Tạo key mới
        db.run(
            'INSERT INTO keys (key, expires_at) VALUES (?, ?)',
            [newKey, expiresAt.toISOString()],
            function(err) {
                if (err) {
                    console.error('Insert error:', err);
                    return res.status(500).json({ 
                        success: false, 
                        message: 'Lỗi khi tạo key' 
                    });
                }
                
                res.json({ 
                    success: true, 
                    key: newKey, 
                    expires: expiresAt.toISOString(),
                    message: 'Key đã được tạo thành công'
                });
            }
        );
    } catch (error) {
        console.error('Error in /get-key:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Lỗi server nội bộ' 
        });
    }
});

// API xác thực key (lưu user_id khi verify)
app.post('/verify-key', (req, res) => {
    try {
        const { key, user_id } = req.body;
        
        if (!key) {
            return res.json({ 
                valid: false, 
                reason: 'Thiếu key' 
            });
        }
        
        db.get(
            'SELECT * FROM keys WHERE key = ?',
            [key],
            (err, row) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ 
                        valid: false, 
                        reason: 'Lỗi server' 
                    });
                }
                
                if (!row) {
                    return res.json({ 
                        valid: false, 
                        reason: 'Key không tồn tại' 
                    });
                }
                
                // Kiểm tra hết hạn
                const now = new Date();
                const expiresAt = new Date(row.expires_at);
                if (now > expiresAt) {
                    return res.json({ 
                        valid: false, 
                        reason: 'Key đã hết hạn' 
                    });
                }
                
                if (row.used) {
                    // Kiểm tra nếu key đã được sử dụng bởi user khác
                    if (row.user_id !== user_id) {
                        return res.json({ 
                            valid: false, 
                            reason: 'Key đã được sử dụng bởi user khác' 
                        });
                    }
                    // Nếu là cùng user thì vẫn hợp lệ
                    return res.json({ 
                        valid: true,
                        user_id: row.user_id,
                        created_at: row.created_at,
                        expires_at: row.expires_at
                    });
                }
                
                // Lưu user_id và đánh dấu đã sử dụng
                db.run(
                    'UPDATE keys SET used = TRUE, user_id = ? WHERE key = ?',
                    [user_id, key],
                    function(err) {
                        if (err) {
                            console.error('Lỗi khi cập nhật key:', err);
                        }
                    }
                );
                
                res.json({ 
                    valid: true,
                    user_id: user_id,
                    created_at: row.created_at,
                    expires_at: row.expires_at
                });
            }
        );
    } catch (error) {
        console.error('Error in /verify-key:', error);
        res.status(500).json({ 
            valid: false, 
            reason: 'Lỗi server nội bộ' 
        });
    }
});

// API kiểm tra key info
app.get('/key-info/:key', (req, res) => {
    const { key } = req.params;
    
    db.get(
        'SELECT * FROM keys WHERE key = ?',
        [key],
        (err, row) => {
            if (err) {
                return res.status(500).json({ 
                    error: 'Lỗi database' 
                });
            }
            
            if (!row) {
                return res.json({ 
                    exists: false,
                    message: 'Key không tồn tại'
                });
            }
            
            res.json({
                exists: true,
                key: row.key,
                user_id: row.user_id,
                created_at: row.created_at,
                expires_at: row.expires_at,
                used: row.used === 1,
                is_expired: new Date() > new Date(row.expires_at)
            });
        }
    );
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        service: 'Key System API',
        url: 'https://qqwq-2.onrender.com/'
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({ 
        message: 'Key System API đang hoạt động',
        endpoints: {
            health: '/health',
            getKey: 'POST /get-key',
            verifyKey: 'POST /verify-key',
            keyInfo: 'GET /key-info/:key'
        }
    });
});

// Khởi động server
app.listen(PORT, () => {
    console.log(`🚀 Server đang chạy trên port ${PORT}`);
    console.log(`📊 Health check: https://qqwq-2.onrender.com/health`);
});
