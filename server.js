const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();

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

// Tạo bảng keys
db.run(`CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    hwid TEXT,
    user_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    used BOOLEAN DEFAULT FALSE
)`);

// Tạo bảng requests để theo dõi thời gian request
db.run(`CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hwid TEXT NOT NULL,
    last_request_time DATETIME NOT NULL,
    request_count INTEGER DEFAULT 1
)`);

// Hàm tạo key ngẫu nhiên
function generateRandomKey(length = 5) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return `key-${result}`;
}

// API tạo key mới với kiểm tra HWID và thời gian 24h
app.post('/get-key', (req, res) => {
    try {
        const { hwid } = req.body;
        
        if (!hwid) {
            return res.status(400).json({ 
                success: false, 
                message: 'Thiếu HWID' 
            });
        }
        
        const now = new Date();
        
        // Kiểm tra xem HWID đã request key trước đó chưa
        db.get(
            'SELECT * FROM requests WHERE hwid = ?',
            [hwid],
            (err, row) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ 
                        success: false, 
                        message: 'Lỗi server' 
                    });
                }
                
                if (row) {
                    // Kiểm tra thời gian từ lần request cuối
                    const lastRequestTime = new Date(row.last_request_time);
                    const timeDiff = now - lastRequestTime;
                    const hoursDiff = timeDiff / (1000 * 60 * 60);
                    
                    if (hoursDiff < 24) {
                        const timeLeft = 24 - hoursDiff;
                        const hoursLeft = Math.floor(timeLeft);
                        const minutesLeft = Math.floor((timeLeft - hoursLeft) * 60);
                        
                        return res.status(429).json({ 
                            success: false, 
                            message: `Bạn phải chờ ${hoursLeft} giờ ${minutesLeft} phút nữa để lấy key mới`,
                            time_left: timeLeft
                        });
                    }
                    
                    // Cập nhật thời gian request
                    db.run(
                        'UPDATE requests SET last_request_time = ?, request_count = request_count + 1 WHERE hwid = ?',
                        [now.toISOString(), hwid],
                        (err) => {
                            if (err) {
                                console.error('Update request error:', err);
                            }
                        }
                    );
                } else {
                    // Thêm request mới
                    db.run(
                        'INSERT INTO requests (hwid, last_request_time) VALUES (?, ?)',
                        [hwid, now.toISOString()],
                        (err) => {
                            if (err) {
                                console.error('Insert request error:', err);
                            }
                        }
                    );
                }
                
                // Tạo key mới
                const newKey = generateRandomKey(5);
                const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 giờ
                
                db.run(
                    'INSERT INTO keys (key, hwid, expires_at) VALUES (?, ?, ?)',
                    [newKey, hwid, expiresAt.toISOString()],
                    function(err) {
                        if (err) {
                            console.error('Insert key error:', err);
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
        
        if (!user_id) {
            return res.json({ 
                valid: false, 
                reason: 'Thiếu user_id' 
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
                hwid: row.hwid,
                created_at: row.created_at,
                expires_at: row.expires_at,
                used: row.used === 1,
                is_expired: new Date() > new Date(row.expires_at)
            });
        }
    );
});

// API kiểm tra thời gian chờ còn lại theo HWID
app.post('/check-time-left', (req, res) => {
    try {
        const { hwid } = req.body;
        
        if (!hwid) {
            return res.status(400).json({ 
                success: false, 
                message: 'Thiếu HWID' 
            });
        }
        
        db.get(
            'SELECT * FROM requests WHERE hwid = ?',
            [hwid],
            (err, row) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ 
                        success: false, 
                        message: 'Lỗi server' 
                    });
                }
                
                if (!row) {
                    return res.json({ 
                        can_request: true,
                        time_left: 0,
                        message: 'Bạn có thể lấy key ngay bây giờ'
                    });
                }
                
                const lastRequestTime = new Date(row.last_request_time);
                const now = new Date();
                const timeDiff = now - lastRequestTime;
                const hoursDiff = timeDiff / (1000 * 60 * 60);
                
                if (hoursDiff >= 1) {
                    return res.json({ 
                        can_request: true,
                        time_left: 0,
                        message: 'Bạn có thể lấy key ngay bây giờ'
                    });
                } else {
                    const timeLeft = 1 - hoursDiff;
                    const hoursLeft = Math.floor(timeLeft);
                    const minutesLeft = Math.floor((timeLeft - hoursLeft) * 60);
                    
                    return res.json({ 
                        can_request: false,
                        time_left: timeLeft,
                        message: `Bạn phải chờ ${hoursLeft} giờ ${minutesLeft} phút nữa để lấy key mới`
                    });
                }
            }
        );
    } catch (error) {
        console.error('Error in /check-time-left:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Lỗi server nội bộ' 
        });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        service: 'Key System API'
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
            keyInfo: 'GET /key-info/:key',
            checkTimeLeft: 'POST /check-time-left'
        }
    });
});

// Khởi động server
app.listen(PORT, () => {
    console.log(`🚀 Server đang chạy trên port ${PORT}`);
});
