const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

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
    username TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    banned BOOLEAN DEFAULT FALSE
)`);

// Tạo bảng requests để theo dõi thời gian request
db.run(`CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hwid TEXT NOT NULL,
    last_request_time DATETIME NOT NULL,
    request_count INTEGER DEFAULT 1
)`);

// Tạo bảng admin để lưu thông tin đăng nhập admin
db.run(`CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)`);

// Thêm admin mặc định nếu chưa có
const adminPassword = 'tungdeptrai1202';
bcrypt.hash(adminPassword, 10, (err, hash) => {
    if (err) {
        console.error('Lỗi khi hash password admin:', err);
        return;
    }
    
    db.get('SELECT * FROM admin WHERE username = ?', ['admin'], (err, row) => {
        if (err) {
            console.error('Lỗi khi kiểm tra admin:', err);
            return;
        }
        
        if (!row) {
            db.run('INSERT INTO admin (username, password) VALUES (?, ?)', ['admin', hash], (err) => {
                if (err) {
                    console.error('Lỗi khi tạo admin mặc định:', err);
                } else {
                    console.log('Admin mặc định đã được tạo. Username: admin, Password: tungdeptrai1202');
                }
            });
        }
    });
});

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

// API xác thực key (lưu user_id và username khi verify)
app.post('/verify-key', (req, res) => {
    try {
        const { key, user_id, username } = req.body;
        
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
                
                // Kiểm tra nếu key bị banned
                if (row.banned) {
                    return res.json({ 
                        valid: false, 
                        reason: 'Key đã bị khóa' 
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
                        username: row.username,
                        created_at: row.created_at,
                        expires_at: row.expires_at
                    });
                }
                
                // Lưu user_id, username và đánh dấu đã sử dụng
                db.run(
                    'UPDATE keys SET used = TRUE, user_id = ?, username = ? WHERE key = ?',
                    [user_id, username, key],
                    function(err) {
                        if (err) {
                            console.error('Lỗi khi cập nhật key:', err);
                        }
                    }
                );
                
                res.json({ 
                    valid: true,
                    user_id: user_id,
                    username: username,
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

// API lấy danh sách tất cả keys (chỉ admin)
app.get('/admin/keys', (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token không hợp lệ' });
    }
    
    const token = authHeader.substring(7);
    
    // Kiểm tra token admin
    if (token !== 'tungdeptrai1202') {
        return res.status(403).json({ error: 'Không có quyền truy cập' });
    }
    
    db.all('SELECT * FROM keys ORDER BY created_at DESC', (err, rows) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        res.json(rows);
    });
});

// API lấy danh sách tất cả users (chỉ admin)
app.get('/admin/users', (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token không hợp lệ' });
    }
    
    const token = authHeader.substring(7);
    
    // Kiểm tra token admin
    if (token !== 'tungdeptrai1202') {
        return res.status(403).json({ error: 'Không có quyền truy cập' });
    }
    
    db.all('SELECT DISTINCT user_id, username, COUNT(*) as key_count, MAX(created_at) as last_used FROM keys WHERE user_id IS NOT NULL GROUP BY user_id ORDER BY last_used DESC', (err, rows) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        res.json(rows);
    });
});

// API ban user (chỉ admin)
app.post('/admin/ban-user', (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token không hợp lệ' });
    }
    
    const token = authHeader.substring(7);
    
    // Kiểm tra token admin
    if (token !== 'tungdeptrai1202') {
        return res.status(403).json({ error: 'Không có quyền truy cập' });
    }
    
    const { user_id } = req.body;
    
    if (!user_id) {
        return res.status(400).json({ error: 'Thiếu user_id' });
    }
    
    db.run('UPDATE keys SET banned = TRUE WHERE user_id = ?', [user_id], function(err) {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        res.json({ 
            success: true, 
            message: `Đã ban user ${user_id}`,
            changes: this.changes
        });
    });
});

// API unban user (chỉ admin)
app.post('/admin/unban-user', (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token không hợp lệ' });
    }
    
    const token = authHeader.substring(7);
    
    // Kiểm tra token admin
    if (token !== 'tungdeptrai1202') {
        return res.status(403).json({ error: 'Không có quyền truy cập' });
    }
    
    const { user_id } = req.body;
    
    if (!user_id) {
        return res.status(400).json({ error: 'Thiếu user_id' });
    }
    
    db.run('UPDATE keys SET banned = FALSE WHERE user_id = ?', [user_id], function(err) {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        res.json({ 
            success: true, 
            message: `Đã unban user ${user_id}`,
            changes: this.changes
        });
    });
});

// API chỉnh sửa thời gian key (chỉ admin)
app.post('/admin/update-key-expiry', (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token không hợp lệ' });
    }
    
    const token = authHeader.substring(7);
    
    // Kiểm tra token admin
    if (token !== 'tungdeptrai1202') {
        return res.status(403).json({ error: 'Không có quyền truy cập' });
    }
    
    const { key, hours } = req.body;
    
    if (!key || !hours) {
        return res.status(400).json({ error: 'Thiếu key hoặc hours' });
    }
    
    const newExpiry = new Date(Date.now() + hours * 60 * 60 * 1000);
    
    db.run('UPDATE keys SET expires_at = ? WHERE key = ?', [newExpiry.toISOString(), key], function(err) {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Key không tồn tại' });
        }
        
        res.json({ 
            success: true, 
            message: `Đã cập nhật thời gian key ${key} thành ${hours} giờ`,
            new_expiry: newExpiry.toISOString()
        });
    });
});

// API tạo key mới (chỉ admin)
app.post('/admin/create-key', (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token không hợp lệ' });
    }
    
    const token = authHeader.substring(7);
    
    // Kiểm tra token admin
    if (token !== 'tungdeptrai1202') {
        return res.status(403).json({ error: 'Không có quyền truy cập' });
    }
    
    const { hours = 24 } = req.body;
    
    const newKey = generateRandomKey(5);
    const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000);
    
    db.run('INSERT INTO keys (key, expires_at) VALUES (?, ?)', [newKey, expiresAt.toISOString()], function(err) {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi khi tạo key' });
        }
        
        res.json({ 
            success: true, 
            key: newKey, 
            expires: expiresAt.toISOString(),
            message: 'Key đã được tạo thành công'
        });
    });
});

// API xóa key (chỉ admin)
app.delete('/admin/delete-key/:key', (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token không hợp lệ' });
    }
    
    const token = authHeader.substring(7);
    
    // Kiểm tra token admin
    if (token !== 'tungdeptrai1202') {
        return res.status(403).json({ error: 'Không có quyền truy cập' });
    }
    
    const { key } = req.params;
    
    db.run('DELETE FROM keys WHERE key = ?', [key], function(err) {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Key không tồn tại' });
        }
        
        res.json({ 
            success: true, 
            message: `Đã xóa key ${key}`
        });
    });
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
                username: row.username,
                hwid: row.hwid,
                created_at: row.created_at,
                expires_at: row.expires_at,
                used: row.used === 1,
                banned: row.banned === 1,
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

// Admin login endpoint
app.post('/admin/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Thiếu username hoặc password' });
    }
    
    db.get('SELECT * FROM admin WHERE username = ?', [username], (err, row) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi server' });
        }
        
        if (!row) {
            return res.status(401).json({ error: 'Sai thông tin đăng nhập' });
        }
        
        bcrypt.compare(password, row.password, (err, result) => {
            if (err) {
                console.error('Lỗi khi so sánh password:', err);
                return res.status(500).json({ error: 'Lỗi server' });
            }
            
            if (result) {
                res.json({ 
                    success: true, 
                    token: 'tungdeptrai1202',
                    message: 'Đăng nhập thành công'
                });
            } else {
                res.status(401).json({ error: 'Sai thông tin đăng nhập' });
            }
        });
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
            checkTimeLeft: 'POST /check-time-left',
            adminLogin: 'POST /admin/login'
        }
    });
});

// Khởi động server
app.listen(PORT, () => {
    console.log(`🚀 Server đang chạy trên port ${PORT}`);
});
