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
    username TEXT,
    ip TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    used_at DATETIME,
    used_by TEXT
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

// API tạo key mới với user_id
app.post('/get-key', (req, res) => {
    try {
        const userIp = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        const { user_id, username } = req.body;
        
        if (!user_id) {
            return res.status(400).json({ 
                success: false, 
                message: 'Thiếu user_id' 
            });
        }
        
        const newKey = generateRandomKey(20);
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 giờ
        
        // Kiểm tra xem user_id đã có key chưa hết hạn chưa
        db.get(
            'SELECT * FROM keys WHERE user_id = ? AND expires_at > datetime("now") AND used = FALSE',
            [user_id],
            (err, row) => {
                if (err) {
                    console.error('Database error:', err);
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
                    'INSERT INTO keys (key, user_id, username, ip, expires_at) VALUES (?, ?, ?, ?, ?)',
                    [newKey, user_id, username || 'Unknown', userIp, expiresAt.toISOString()],
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

// API xác thực key với user_id
app.post('/verify-key', (req, res) => {
    try {
        const { key, user_id, username } = req.body;
        
        if (!key || !user_id) {
            return res.json({ 
                valid: false, 
                reason: 'Thiếu key hoặc user_id' 
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
                    return res.json({ 
                        valid: false, 
                        reason: 'Key đã được sử dụng' 
                    });
                }
                
                if (row.user_id && row.user_id !== user_id) {
                    return res.json({ 
                        valid: false, 
                        reason: 'Key không thuộc về user này' 
                    });
                }
                
                // Đánh dấu key đã sử dụng
                const usedAt = new Date().toISOString();
                db.run(
                    'UPDATE keys SET used = TRUE, used_at = ?, used_by = ? WHERE key = ?',
                    [usedAt, username || 'Unknown', key],
                    function(err) {
                        if (err) {
                            console.error('Lỗi khi cập nhật key:', err);
                        }
                    }
                );
                
                res.json({ 
                    valid: true,
                    user_id: row.user_id,
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

// API lấy thông tin key theo user_id
app.get('/key-info/:user_id', (req, res) => {
    const { user_id } = req.params;
    
    db.get(
        'SELECT * FROM keys WHERE user_id = ? ORDER BY created_at DESC LIMIT 1',
        [user_id],
        (err, row) => {
            if (err) {
                return res.status(500).json({ 
                    error: 'Lỗi database' 
                });
            }
            
            if (!row) {
                return res.json({ 
                    exists: false,
                    message: 'Không tìm thấy key cho user này'
                });
            }
            
            res.json({
                exists: true,
                key: row.key,
                user_id: row.user_id,
                username: row.username,
                created_at: row.created_at,
                expires_at: row.expires_at,
                used: row.used === 1,
                used_at: row.used_at,
                used_by: row.used_by
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
            keyInfo: 'GET /key-info/:user_id'
        },
        documentation: 'Sử dụng POST /get-key với {user_id, username} để tạo key'
    });
});

// Xử lý lỗi 404
app.use('*', (req, res) => {
    res.status(404).json({ 
        error: 'Endpoint không tồn tại',
        available_endpoints: {
            health: 'GET /health',
            getKey: 'POST /get-key',
            verifyKey: 'POST /verify-key',
            keyInfo: 'GET /key-info/:user_id'
        }
    });
});

// Xử lý lỗi global
app.use((error, req, res, next) => {
    console.error('Global error handler:', error);
    res.status(500).json({ 
        error: 'Lỗi server nội bộ',
        message: error.message 
    });
});

// Khởi động server
app.listen(PORT, () => {
    console.log(`🚀 Server đang chạy trên port ${PORT}`);
    console.log(`📊 Health check: https://qqwq-2.onrender.com/health`);
    console.log(`🌐 Server URL: https://qqwq-2.onrender.com/`);
});
