const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = 'tungdeptrai1202';

// Create HTTP server and Socket.IO instance
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: '*',
        methods: ['GET', 'POST']
    }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Đảm bảo thư mục data tồn tại
const dataDir = './data';
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir);
}

// Khởi tạo database với đường dẫn cố định trong thư mục data
const dbPath = path.join(dataDir, 'keys.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Lỗi kết nối database:', err);
    } else {
        console.log('Kết nối SQLite thành công tại:', dbPath);
    }
});

// Tạo bảng keys với cấu trúc lưu trữ vĩnh viễn
db.run(`CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    hwid TEXT,
    user_id TEXT,
    username TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    used BOOLEAN DEFAULT FALSE,
    banned BOOLEAN DEFAULT FALSE,
    permanent BOOLEAN DEFAULT FALSE
)`);

// Tạo bảng requests để theo dõi thời gian request
db.run(`CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hwid TEXT NOT NULL,
    last_request_time DATETIME NOT NULL,
    request_count INTEGER DEFAULT 1
)`);

// Tạo bảng admin để lưu thông tin đăng nhập admin (vĩnh viễn)
db.run(`CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_super_admin BOOLEAN DEFAULT FALSE,
    is_owner BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Tạo bảng users để lưu thông tin user vĩnh viễn
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    total_keys_used INTEGER DEFAULT 0,
    banned BOOLEAN DEFAULT FALSE
)`);

// Tạo bảng lịch sử hoạt động admin
db.run(`CREATE TABLE IF NOT EXISTS admin_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_username TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT,
    target_value TEXT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Tạo bảng chat admin
db.run(`CREATE TABLE IF NOT EXISTS admin_chat (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_username TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Tạo bảng lịch sử key của user
db.run(`CREATE TABLE IF NOT EXISTS user_key_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    key TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Thêm owner mặc định nếu chưa có
const ownerPassword = 'tungdeptrai1202';
bcrypt.hash(ownerPassword, 10, (err, hash) => {
    if (err) {
        console.error('Lỗi khi hash password owner:', err);
        return;
    }
    
    db.get('SELECT * FROM admin WHERE username = ?', ['owner'], (err, row) => {
        if (err) {
            console.error('Lỗi khi kiểm tra owner:', err);
            return;
        }
        
        if (!row) {
            db.run('INSERT INTO admin (username, password, is_super_admin, is_owner) VALUES (?, ?, ?, ?)', 
                   ['owner', hash, true, true], (err) => {
                if (err) {
                    console.error('Lỗi khi tạo owner mặc định:', err);
                } else {
                    console.log('Owner mặc định đã được tạo. Username: owner, Password: tungdeptrai1202');
                }
            });
        }
    });
});

// Hàm ghi log hoạt động admin
function logAdminActivity(adminUsername, action, targetType = null, targetValue = null, details = null) {
    db.run(
        'INSERT INTO admin_activity (admin_username, action, target_type, target_value, details) VALUES (?, ?, ?, ?, ?)',
        [adminUsername, action, targetType, targetValue, details],
        (err) => {
            if (err) {
                console.error('Lỗi khi ghi log hoạt động admin:', err);
            }
        }
    );
}

// Hàm ghi log hoạt động key của user
function logUserKeyActivity(userId, key, action, details = null) {
    db.run(
        'INSERT INTO user_key_history (user_id, key, action, details) VALUES (?, ?, ?, ?)',
        [userId, key, action, details],
        (err) => {
            if (err) {
                console.error('Lỗi khi ghi log hoạt động key của user:', err);
            }
        }
    );
}

// Hàm tạo key ngẫu nhiên
function generateRandomKey(length = 5, prefix = 'key-') {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return `${prefix}${result}`;
}

// Hàm cập nhật thông tin user
function updateUserInfo(user_id, username) {
    if (!user_id) return;
    
    db.get('SELECT * FROM users WHERE user_id = ?', [user_id], (err, row) => {
        if (err) {
            console.error('Lỗi khi kiểm tra user:', err);
            return;
        }
        
        if (row) {
            db.run(
                'UPDATE users SET username = ?, last_seen = CURRENT_TIMESTAMP, total_keys_used = total_keys_used + 1 WHERE user_id = ?',
                [username, user_id],
                (err) => {
                    if (err) {
                        console.error('Lỗi khi cập nhật user:', err);
                    }
                }
            );
        } else {
            db.run(
                'INSERT INTO users (user_id, username) VALUES (?, ?)',
                [user_id, username],
                (err) => {
                    if (err) {
                        console.error('Lỗi khi thêm user mới:', err);
                    }
                }
            );
        }
    });
}

// Middleware xác thực vai trò cho HTTP
function authenticateRole(roles = []) {
    return (req, res, next) => {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Token không hợp lệ' });
        }
        
        const token = authHeader.substring(7);
        
        try {
            const decoded = jwt.verify(token, SECRET);
            req.user = decoded;
            const userRole = decoded.is_owner ? 'owner' : (decoded.is_super_admin ? 'super_admin' : 'admin');
            
            if (roles.length === 0 || roles.includes(userRole)) {
                next();
            } else {
                return res.status(403).json({ error: 'Không có quyền truy cập' });
            }
        } catch (err) {
            return res.status(401).json({ error: 'Token không hợp lệ' });
        }
    };
}

// Socket.IO authentication middleware
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        return next(new Error('Token không hợp lệ'));
    }

    try {
        const decoded = jwt.verify(token, SECRET);
        const userRole = decoded.is_owner ? 'owner' : (decoded.is_super_admin ? 'super_admin' : 'admin');
        if (!['admin', 'super_admin', 'owner'].includes(userRole)) {
            return next(new Error('Không có quyền truy cập'));
        }
        socket.user = decoded;
        next();
    } catch (err) {
        next(new Error('Token không hợp lệ'));
    }
});

// Socket.IO chat handling
io.on('connection', (socket) => {
    const username = socket.user.username;
    console.log(`Admin ${username} connected to chat`);

    // Send chat history on connection
    db.all('SELECT * FROM admin_chat ORDER BY created_at DESC LIMIT 50', (err, rows) => {
        if (err) {
            console.error('Lỗi khi lấy lịch sử chat:', err);
            return;
        }
        socket.emit('history', rows.reverse());
    });

    // Handle incoming messages
    socket.on('message', (msg) => {
        if (!msg || typeof msg !== 'string' || msg.trim() === '') {
            socket.emit('error', { message: 'Tin nhắn không hợp lệ' });
            return;
        }

        const message = msg.trim();
        db.run('INSERT INTO admin_chat (admin_username, message) VALUES (?, ?)', 
            [username, message], 
            function(err) {
                if (err) {
                    console.error('Lỗi khi lưu tin nhắn:', err);
                    socket.emit('error', { message: 'Lỗi khi lưu tin nhắn' });
                    return;
                }

                const chatMessage = {
                    id: this.lastID,
                    admin_username: username,
                    message: message,
                    created_at: new Date().toISOString()
                };

                // Broadcast message to all connected clients
                io.emit('message', chatMessage);
            }
        );
    });

    socket.on('disconnect', () => {
        console.log(`Admin ${username} disconnected from chat`);
    });
});

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
                
                const newKey = generateRandomKey(5);
                const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
                
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
                
                if (row.banned) {
                    return res.json({ 
                        valid: false, 
                        reason: 'Key đã bị khóa' 
                    });
                }
                
                const now = new Date();
                const expiresAt = new Date(row.expires_at);
                if (now > expiresAt && !row.permanent) {
                    return res.json({ 
                        valid: false, 
                        reason: 'Key đã hết hạn' 
                    });
                }
                
                if (row.used) {
                    if (row.user_id !== user_id) {
                        return res.json({ 
                            valid: false, 
                            reason: 'Key đã được sử dụng bởi user khác' 
                        });
                    }
                    return res.json({ 
                        valid: true,
                        user_id: row.user_id,
                        username: row.username,
                        created_at: row.created_at,
                        expires_at: row.expires_at,
                        permanent: row.permanent
                    });
                }
                
                updateUserInfo(user_id, username);
                logUserKeyActivity(user_id, key, 'verify', `Key verified by ${username}`);
                
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
                    expires_at: row.expires_at,
                    permanent: row.permanent
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
app.get('/admin/keys', authenticateRole(['admin', 'super_admin', 'owner']), (req, res) => {
    db.all('SELECT * FROM keys ORDER BY created_at DESC', (err, rows) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        res.json(rows);
    });
});

// API lấy danh sách tất cả users (chỉ admin)
app.get('/admin/users', authenticateRole(['admin', 'super_admin', 'owner']), (req, res) => {
    db.all('SELECT * FROM users ORDER BY last_seen DESC', (err, rows) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        res.json(rows);
    });
});

// API lấy danh sách admin (chỉ super admin và owner)
app.get('/admin/admins', authenticateRole(['super_admin', 'owner']), (req, res) => {
    db.all('SELECT id, username, is_super_admin, is_owner, created_at FROM admin ORDER BY created_at DESC', (err, rows) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        res.json(rows);
    });
});

// API lấy lịch sử hoạt động admin (chỉ owner)
app.get('/admin/activity', authenticateRole(['owner']), (req, res) => {
    const limit = req.query.limit || 100;
    
    db.all('SELECT * FROM admin_activity ORDER BY created_at DESC LIMIT ?', [limit], (err, rows) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        res.json(rows);
    });
});

// API lấy lịch sử key của user (chỉ admin)
app.get('/admin/user-key-history/:user_id', authenticateRole(['admin', 'super_admin', 'owner']), (req, res) => {
    const { user_id } = req.params;
    const limit = req.query.limit || 50;
    
    db.all('SELECT * FROM user_key_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?', [user_id, limit], (err, rows) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        res.json(rows);
    });
});

// API ban user (chỉ admin)
app.post('/admin/ban-user', authenticateRole(['admin', 'super_admin', 'owner']), (req, res) => {
    const { user_id } = req.body;
    const admin_username = req.user.username;
    
    if (!user_id) {
        return res.status(400).json({ error: 'Thiếu user_id' });
    }
    
    db.run('UPDATE keys SET banned = TRUE WHERE user_id = ?', [user_id], function(err) {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        db.run('UPDATE users SET banned = TRUE WHERE user_id = ?', [user_id], function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Lỗi database' });
            }
            
            logAdminActivity(admin_username, 'ban_user', 'user', user_id, `Banned user ${user_id}`);
            
            res.json({ 
                success: true, 
                message: `Đã ban user ${user_id}`,
                changes: this.changes
            });
        });
    });
});

// API unban user (chỉ admin)
app.post('/admin/unban-user', authenticateRole(['admin', 'super_admin', 'owner']), (req, res) => {
    const { user_id } = req.body;
    const admin_username = req.user.username;
    
    if (!user_id) {
        return res.status(400).json({ error: 'Thiếu user_id' });
    }
    
    db.run('UPDATE keys SET banned = FALSE WHERE user_id = ?', [user_id], function(err) {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        db.run('UPDATE users SET banned = FALSE WHERE user_id = ?', [user_id], function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Lỗi database' });
            }
            
            logAdminActivity(admin_username, 'unban_user', 'user', user_id, `Unbanned user ${user_id}`);
            
            res.json({ 
                success: true, 
                message: `Đã unban user ${user_id}`,
                changes: this.changes
            });
        });
    });
});

// API chỉnh sửa thời gian key (chỉ admin)
app.post('/admin/update-key-expiry', authenticateRole(['admin', 'super_admin', 'owner']), (req, res) => {
    const { key, hours, permanent } = req.body;
    const admin_username = req.user.username;
    
    if (!key) {
        return res.status(400).json({ error: 'Thiếu key' });
    }
    
    if (permanent) {
        db.run('UPDATE keys SET permanent = TRUE, expires_at = NULL WHERE key = ?', [key], function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Lỗi database' });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Key không tồn tại' });
            }
            
            logAdminActivity(admin_username, 'update_key', 'key', key, 'Set key to permanent');
            
            res.json({ 
                success: true, 
                message: `Đã đặt key ${key} thành vĩnh viễn`,
                permanent: true
            });
        });
    } else if (hours) {
        const newExpiry = new Date(Date.now() + hours * 60 * 60 * 1000);
        
        db.run('UPDATE keys SET expires_at = ?, permanent = FALSE WHERE key = ?', [newExpiry.toISOString(), key], function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Lỗi database' });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Key không tồn tại' });
            }
            
            logAdminActivity(admin_username, 'update_key', 'key', key, `Set key expiry to ${hours} hours`);
            
            res.json({ 
                success: true, 
                message: `Đã cập nhật thời gian key ${key} thành ${hours} giờ`,
                new_expiry: newExpiry.toISOString(),
                permanent: false
            });
        });
    } else {
        return res.status(400).json({ error: 'Thiếu hours hoặc permanent' });
    }
});

// API tạo key mới (chỉ admin)
app.post('/admin/create-key', authenticateRole(['admin', 'super_admin', 'owner']), (req, res) => {
    const { hours = 24, permanent = false, keyPrefix = 'key-' } = req.body;
    const admin_username = req.user.username;

    // Validate keyPrefix
    if (typeof keyPrefix !== 'string' || keyPrefix.trim() === '') {
        console.error('Invalid keyPrefix:', keyPrefix, 'Type:', typeof keyPrefix);
        return res.status(400).json({ error: 'keyPrefix phải là chuỗi không rỗng' });
    }

    const safePrefix = keyPrefix.trim();
    const newKey = generateRandomKey(5, safePrefix);
    let expiresAt = null;
    
    if (!permanent) {
        expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000);
    }
    
    db.run('INSERT INTO keys (key, expires_at, permanent) VALUES (?, ?, ?)', 
        [newKey, expiresAt ? expiresAt.toISOString() : null, permanent], 
        function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Lỗi khi tạo key' });
            }
            
            logAdminActivity(admin_username, 'create_key', 'key', newKey, `Created ${permanent ? 'permanent' : hours + ' hours'} key`);
            
            res.json({ 
                success: true, 
                key: newKey, 
                expires: expiresAt ? expiresAt.toISOString() : null,
                permanent: permanent,
                message: 'Key đã được tạo thành công'
            });
        }
    );
});

// API xóa key (chỉ admin)
app.delete('/admin/delete-key/:key', authenticateRole(['admin', 'super_admin', 'owner']), (req, res) => {
    const { key } = req.params;
    const admin_username = req.user.username;
    
    db.run('DELETE FROM keys WHERE key = ?', [key], function(err) {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Key không tồn tại' });
        }
        
        logAdminActivity(admin_username, 'delete_key', 'key', key, 'Deleted key');
        
        res.json({ 
            success: true, 
            message: `Đã xóa key ${key}`
        });
    });
});

// API tạo admin mới (chỉ super admin và owner)
app.post('/admin/create-admin', authenticateRole(['super_admin', 'owner']), (req, res) => {
    const { username, password } = req.body;
    const admin_username = req.user.username;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Thiếu username hoặc password' });
    }
    
    db.get('SELECT * FROM admin WHERE username = ?', [username], (err, row) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        if (row) {
            return res.status(400).json({ error: 'Admin đã tồn tại' });
        }
        
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                console.error('Lỗi khi hash password:', err);
                return res.status(500).json({ error: 'Lỗi server' });
            }
            
            db.run('INSERT INTO admin (username, password) VALUES (?, ?)', 
                   [username, hash], function(err) {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ error: 'Lỗi khi tạo admin' });
                }
                
                logAdminActivity(admin_username, 'create_admin', 'admin', username, 'Created new admin');
                
                res.json({ 
                    success: true, 
                    message: `Đã tạo admin ${username} thành công`
                });
            });
        });
    });
});

// API xóa admin (chỉ owner)
app.delete('/admin/delete-admin/:username', authenticateRole(['owner']), (req, res) => {
    const { username } = req.params;
    const admin_username = req.user.username;
    
    if (username === 'owner') {
        return res.status(400).json({ error: 'Không thể xóa owner' });
    }
    
    db.run('DELETE FROM admin WHERE username = ?', [username], function(err) {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Admin không tồn tại' });
        }
        
        logAdminActivity(admin_username, 'delete_admin', 'admin', username, 'Deleted admin');
        
        res.json({ 
            success: true, 
            message: `Đã xóa admin ${username}`
        });
    });
});

// API cập nhật quyền admin (chỉ owner)
app.post('/admin/update-admin-role', authenticateRole(['owner']), (req, res) => {
    const { username, is_super_admin } = req.body;
    const admin_username = req.user.username;
    
    if (!username) {
        return res.status(400).json({ error: 'Thiếu username' });
    }
    
    if (username === 'owner') {
        return res.status(400).json({ error: 'Không thể thay đổi quyền owner' });
    }
    
    db.run('UPDATE admin SET is_super_admin = ? WHERE username = ?', 
           [is_super_admin, username], function(err) {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Admin không tồn tại' });
        }
        
        const action = is_super_admin ? 'promote_admin' : 'demote_admin';
        logAdminActivity(admin_username, action, 'admin', username, 
                        `${is_super_admin ? 'Promoted to' : 'Demoted from'} super admin`);
        
        res.json({ 
            success: true, 
            message: `Đã ${is_super_admin ? 'thăng cấp' : 'hạ cấp'} admin ${username}`
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
            
            const now = new Date();
            const expiresAt = row.expires_at ? new Date(row.expires_at) : null;
            const isExpired = expiresAt ? now > expiresAt : false;
            
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
                permanent: row.permanent === 1,
                is_expired: isExpired && !row.permanent
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
        service: 'Key System API',
        database_path: dbPath
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
                const token = jwt.sign({ 
                    username: row.username,
                    is_super_admin: row.is_super_admin,
                    is_owner: row.is_owner 
                }, SECRET, { expiresIn: '1d' });
                
                res.json({ 
                    success: true, 
                    token,
                    is_super_admin: row.is_super_admin,
                    is_owner: row.is_owner,
                    message: 'Đăng nhập thành công'
                });
            } else {
                res.status(401).json({ error: 'Sai thông tin đăng nhập' });
            }
        });
    });
});

// API backup database (chỉ admin)
app.get('/admin/backup', authenticateRole(['admin', 'super_admin', 'owner']), (req, res) => {
    const backupPath = path.join(dataDir, `backup-${Date.now()}.db`);
    
    fs.copyFile(dbPath, backupPath, (err) => {
        if (err) {
            console.error('Lỗi khi tạo backup:', err);
            return res.status(500).json({ error: 'Lỗi khi tạo backup' });
        }
        
        res.json({ 
            success: true, 
            message: 'Backup thành công',
            backup_path: backupPath
        });
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({ 
        message: 'Key System API đang hoạt động',
        database: dbPath,
        endpoints: {
            health: '/health',
            getKey: 'POST /get-key',
            verifyKey: 'POST /verify-key',
            keyInfo: 'GET /key-info/:key',
            checkTimeLeft: 'POST /check-time-left',
            adminLogin: 'POST /admin/login',
            adminBackup: 'GET /admin/backup'
        }
    });
});

// Khởi động server
server.listen(PORT, () => {
    console.log(`🚀 Server đang chạy trên port ${PORT}`);
    console.log(`💾 Database được lưu tại: ${dbPath}`);
});
