const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const fs = require('fs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'tungdeptrai1202_secret_key'; // Change this to a secure secret in production

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Ensure data directory exists
const dataDir = './data';
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir);
}

// Initialize database
const dbPath = path.join(dataDir, 'keys.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Lỗi kết nối database:', err);
    } else {
        console.log('Kết nối SQLite thành công tại:', dbPath);
    }
});

// Create tables
db.run(`CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    hwid TEXT,
    user_id TEXT,
    username TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    verified_at DATETIME,
    used BOOLEAN DEFAULT FALSE,
    banned BOOLEAN DEFAULT FALSE,
    permanent BOOLEAN DEFAULT FALSE
)`);

db.run(`CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hwid TEXT NOT NULL,
    last_request_time DATETIME NOT NULL,
    request_count INTEGER DEFAULT 1
)`);

db.run(`CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    total_keys_used INTEGER DEFAULT 0,
    banned BOOLEAN DEFAULT FALSE
)`);

db.run(`CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_username TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    details TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_username TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Add default owner if not exists
const adminUsername = 'admin';
const adminPassword = 'tungdeptrai1202';
bcrypt.hash(adminPassword, 10, (err, hash) => {
    if (err) {
        console.error('Lỗi khi hash password admin:', err);
        return;
    }
    
    db.get('SELECT * FROM admin WHERE username = ?', [adminUsername], (err, row) => {
        if (err) {
            console.error('Lỗi khi kiểm tra admin:', err);
            return;
        }
        
        if (!row) {
            db.run('INSERT INTO admin (username, password, role) VALUES (?, ?, ?)', 
                   [adminUsername, hash, 2], (err) => {
                if (err) {
                    console.error('Lỗi khi tạo owner mặc định:', err);
                } else {
                    console.log('Owner mặc định đã được tạo. Username: admin, Password: tungdeptrai1202');
                }
            });
        }
    });
});

// Generate random key
function generateRandomKey(length = 5, prefix = 'key-') {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return `${prefix}${result}`;
}

// Update user info
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

// Log admin action
function logAction(db, username, action, target = null, details = null) {
    const detailsStr = details ? JSON.stringify(details) : null;
    db.run('INSERT INTO logs (admin_username, action, target, details) VALUES (?, ?, ?, ?)', 
        [username, action, target, detailsStr], (err) => {
            if (err) {
                console.error('Lỗi khi log action:', err);
            }
        });
}

// Authentication middleware
function authenticateAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token không hợp lệ' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Token không hợp lệ' });
    }
}

function authenticateSuperAdmin(req, res, next) {
    authenticateAdmin(req, res, () => {
        if (req.user.role < 1) {
            return res.status(403).json({ error: 'Yêu cầu quyền super admin hoặc cao hơn' });
        }
        next();
    });
}

function authenticateOwner(req, res, next) {
    authenticateAdmin(req, res, () => {
        if (req.user.role !== 2) {
            return res.status(403).json({ error: 'Yêu cầu quyền owner' });
        }
        next();
    });
}

// API get key
app.post('/get-key', (req, res) => {
    try {
        const { hwid } = req.body;
        
        if (!hwid) {
            return res.status(400).json({ success: false, message: 'Thiếu HWID' });
        }
        
        const now = new Date();
        
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
                    return res.status(429).json({ success: false, message: `Bạn phải chờ ${hoursLeft} giờ ${minutesLeft} phút nữa để lấy key mới`, time_left: timeLeft });
                }
                
                db.run('UPDATE requests SET last_request_time = ?, request_count = request_count + 1 WHERE hwid = ?', [now.toISOString(), hwid]);
            } else {
                db.run('INSERT INTO requests (hwid, last_request_time) VALUES (?, ?)', [hwid, now.toISOString()]);
            }
            
            const newKey = generateRandomKey(5);
            const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
            
            db.run('INSERT INTO keys (key, hwid, expires_at) VALUES (?, ?, ?)', [newKey, hwid, expiresAt.toISOString()], (err) => {
                if (err) {
                    console.error('Insert key error:', err);
                    return res.status(500).json({ success: false, message: 'Lỗi khi tạo key' });
                }
                
                res.json({ success: true, key: newKey, expires: expiresAt.toISOString(), message: 'Key đã được tạo thành công' });
            });
        });
    } catch (error) {
        console.error('Error in /get-key:', error);
        res.status(500).json({ success: false, message: 'Lỗi server nội bộ' });
    }
});

// API verify key
app.post('/verify-key', (req, res) => {
    try {
        const { key, user_id, username } = req.body;
        
        if (!key) {
            return res.json({ valid: false, reason: 'Thiếu key' });
        }
        
        if (!user_id) {
            return res.json({ valid: false, reason: 'Thiếu user_id' });
        }
        
        db.get('SELECT * FROM keys WHERE key = ?', [key], (err, row) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ valid: false, reason: 'Lỗi server' });
            }
            
            if (!row) {
                return res.json({ valid: false, reason: 'Key không tồn tại' });
            }
            
            if (row.banned) {
                return res.json({ valid: false, reason: 'Key đã bị khóa' });
            }
            
            const now = new Date();
            const expiresAt = new Date(row.expires_at);
            if (now > expiresAt && !row.permanent) {
                return res.json({ valid: false, reason: 'Key đã hết hạn' });
            }
            
            if (row.used) {
                if (row.user_id !== user_id) {
                    return res.json({ valid: false, reason: 'Key đã được sử dụng bởi user khác' });
                }
                return res.json({ valid: true, user_id: row.user_id, username: row.username, created_at: row.created_at, expires_at: row.expires_at, permanent: row.permanent });
            }
            
            updateUserInfo(user_id, username);
            
            db.run('UPDATE keys SET used = TRUE, user_id = ?, username = ?, verified_at = CURRENT_TIMESTAMP WHERE key = ?', [user_id, username, key], (err) => {
                if (err) {
                    console.error('Lỗi khi cập nhật key:', err);
                }
            });
            
            res.json({ valid: true, user_id: user_id, username: username, created_at: row.created_at, expires_at: row.expires_at, permanent: row.permanent });
        });
    } catch (error) {
        console.error('Error in /verify-key:', error);
        res.status(500).json({ valid: false, reason: 'Lỗi server nội bộ' });
    }
});

// API get all keys (admin+)
app.get('/admin/keys', authenticateAdmin, (req, res) => {
    db.all('SELECT * FROM keys ORDER BY created_at DESC', (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi database' });
        }
        res.json(rows);
    });
});

// API get all users (admin+)
app.get('/admin/users', authenticateAdmin, (req, res) => {
    db.all('SELECT * FROM users ORDER BY last_seen DESC', (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi database' });
        }
        res.json(rows);
    });
});

// API get admins (super+)
app.get('/admin/admins', authenticateSuperAdmin, (req, res) => {
    db.all('SELECT id, username, role, created_at FROM admin ORDER BY created_at DESC', (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi database' });
        }
        res.json(rows);
    });
});

// API ban user (admin+)
app.post('/admin/ban-user', authenticateAdmin, (req, res) => {
    const { user_id } = req.body;
    
    if (!user_id) {
        return res.status(400).json({ error: 'Thiếu user_id' });
    }
    
    db.run('UPDATE keys SET banned = TRUE WHERE user_id = ?', [user_id], (err) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        db.run('UPDATE users SET banned = TRUE WHERE user_id = ?', [user_id], (err) => {
            if (err) {
                return res.status(500).json({ error: 'Lỗi database' });
            }
            
            logAction(db, req.user.username, 'ban_user', user_id);
            res.json({ success: true, message: `Đã ban user ${user_id}` });
        });
    });
});

// API unban user (admin+)
app.post('/admin/unban-user', authenticateAdmin, (req, res) => {
    const { user_id } = req.body;
    
    if (!user_id) {
        return res.status(400).json({ error: 'Thiếu user_id' });
    }
    
    db.run('UPDATE keys SET banned = FALSE WHERE user_id = ?', [user_id], (err) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        db.run('UPDATE users SET banned = FALSE WHERE user_id = ?', [user_id], (err) => {
            if (err) {
                return res.status(500).json({ error: 'Lỗi database' });
            }
            
            logAction(db, req.user.username, 'unban_user', user_id);
            res.json({ success: true, message: `Đã unban user ${user_id}` });
        });
    });
});

// API update key expiry (admin+)
app.post('/admin/update-key-expiry', authenticateAdmin, (req, res) => {
    const { key, hours, permanent } = req.body;
    
    if (!key) {
        return res.status(400).json({ error: 'Thiếu key' });
    }
    
    if (permanent !== undefined && hours !== undefined) {
        return res.status(400).json({ error: 'Chọn permanent hoặc hours, không cả hai' });
    }
    
    if (permanent) {
        db.run('UPDATE keys SET permanent = TRUE, expires_at = NULL WHERE key = ?', [key], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Lỗi database' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Key không tồn tại' });
            }
            logAction(db, req.user.username, 'update_key_expiry', key, { permanent: true });
            res.json({ success: true, message: `Đã đặt key ${key} thành vĩnh viễn`, permanent: true });
        });
    } else if (hours) {
        const newExpiry = new Date(Date.now() + hours * 60 * 60 * 1000);
        db.run('UPDATE keys SET expires_at = ?, permanent = FALSE WHERE key = ?', [newExpiry.toISOString(), key], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Lỗi database' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Key không tồn tại' });
            }
            logAction(db, req.user.username, 'update_key_expiry', key, { hours });
            res.json({ success: true, message: `Đã cập nhật thời gian key ${key} thành ${hours} giờ`, new_expiry: newExpiry.toISOString(), permanent: false });
        });
    } else {
        return res.status(400).json({ error: 'Thiếu hours hoặc permanent' });
    }
});

// API create key (admin+)
app.post('/admin/create-key', authenticateAdmin, (req, res) => {
    const { hours = 24, permanent = false, keyPrefix = 'key-' } = req.body;
    
    const newKey = generateRandomKey(5, keyPrefix);
    let expiresAt = null;
    
    if (!permanent) {
        expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000);
    }
    
    db.run('INSERT INTO keys (key, expires_at, permanent) VALUES (?, ?, ?)', 
        [newKey, expiresAt ? expiresAt.toISOString() : null, permanent], 
        (err) => {
            if (err) {
                return res.status(500).json({ error: 'Lỗi khi tạo key' });
            }
            logAction(db, req.user.username, 'create_key', newKey, { hours, permanent, keyPrefix });
            res.json({ success: true, key: newKey, expires: expiresAt ? expiresAt.toISOString() : null, permanent, message: 'Key đã được tạo thành công' });
        }
    );
});

// API delete key (admin+)
app.delete('/admin/delete-key/:key', authenticateAdmin, (req, res) => {
    const { key } = req.params;
    
    db.run('DELETE FROM keys WHERE key = ?', [key], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Lỗi database' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Key không tồn tại' });
        }
        logAction(db, req.user.username, 'delete_key', key);
        res.json({ success: true, message: `Đã xóa key ${key}` });
    });
});

// API create admin (super+)
app.post('/admin/create-admin', authenticateSuperAdmin, (req, res) => {
    const { username, password, role = 0 } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Thiếu username hoặc password' });
    }
    
    if (role > 1) {
        return res.status(403).json({ error: 'Không thể tạo owner' });
    }
    
    if (role === 1 && req.user.role !== 2) {
        return res.status(403).json({ error: 'Chỉ owner có thể tạo super admin' });
    }
    
    db.get('SELECT * FROM admin WHERE username = ?', [username], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        if (row) {
            return res.status(400).json({ error: 'Admin đã tồn tại' });
        }
        
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                return res.status(500).json({ error: 'Lỗi server' });
            }
            
            db.run('INSERT INTO admin (username, password, role) VALUES (?, ?, ?)', 
                   [username, hash, role], (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Lỗi khi tạo admin' });
                }
                logAction(db, req.user.username, 'create_admin', username, { role });
                res.json({ success: true, message: `Đã tạo admin ${username} thành công` });
            });
        });
    });
});

// API delete admin (super+)
app.delete('/admin/delete-admin/:username', authenticateSuperAdmin, (req, res) => {
    const { username } = req.params;
    
    db.get('SELECT role FROM admin WHERE username = ?', [username], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi database' });
        }
        if (!row) {
            return res.status(404).json({ error: 'Admin không tồn tại' });
        }
        
        if (row.role >= req.user.role) {
            return res.status(403).json({ error: 'Không thể xóa admin có quyền cao hơn hoặc bằng' });
        }
        
        db.run('DELETE FROM admin WHERE username = ?', [username], (err) => {
            if (err) {
                return res.status(500).json({ error: 'Lỗi database' });
            }
            logAction(db, req.user.username, 'delete_admin', username);
            res.json({ success: true, message: `Đã xóa admin ${username}` });
        });
    });
});

// API update admin role (owner only)
app.post('/admin/update-admin-role', authenticateOwner, (req, res) => {
    const { username, new_role } = req.body;
    
    if (!username || new_role === undefined) {
        return res.status(400).json({ error: 'Thiếu username hoặc new_role' });
    }
    
    if (new_role > 1 || new_role < 0) {
        return res.status(400).json({ error: 'Role không hợp lệ' });
    }
    
    db.get('SELECT role FROM admin WHERE username = ?', [username], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi database' });
        }
        if (!row) {
            return res.status(404).json({ error: 'Admin không tồn tại' });
        }
        
        if (row.role === 2) {
            return res.status(403).json({ error: 'Không thể thay đổi role của owner' });
        }
        
        db.run('UPDATE admin SET role = ? WHERE username = ?', [new_role, username], (err) => {
            if (err) {
                return res.status(500).json({ error: 'Lỗi database' });
            }
            logAction(db, req.user.username, 'update_admin_role', username, { new_role });
            res.json({ success: true, message: `Đã cập nhật role của ${username} thành ${new_role}` });
        });
    });
});

// API get admin logs (owner only)
app.get('/admin/logs', authenticateOwner, (req, res) => {
    const { username, limit = 100 } = req.query;
    let query = 'SELECT * FROM logs';
    const params = [];
    
    if (username) {
        query += ' WHERE admin_username = ?';
        params.push(username);
    }
    
    query += ' ORDER BY timestamp DESC LIMIT ?';
    params.push(parseInt(limit));
    
    db.all(query, params, (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi database' });
        }
        res.json(rows);
    });
});

// API get user keys history (admin+)
app.get('/admin/user-keys/:user_id', authenticateAdmin, (req, res) => {
    const { user_id } = req.params;
    
    db.all('SELECT * FROM keys WHERE user_id = ? ORDER BY created_at DESC', [user_id], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi database' });
        }
        res.json(rows);
    });
});

// API get chat messages (admin+)
app.get('/admin/messages', authenticateAdmin, (req, res) => {
    const { limit = 50 } = req.query;
    
    db.all('SELECT * FROM messages ORDER BY timestamp DESC LIMIT ?', [parseInt(limit)], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi database' });
        }
        res.json(rows);
    });
});

// API send chat message (admin+)
app.post('/admin/message', authenticateAdmin, (req, res) => {
    const { message } = req.body;
    
    if (!message) {
        return res.status(400).json({ error: 'Thiếu message' });
    }
    
    db.run('INSERT INTO messages (sender_username, message) VALUES (?, ?)', [req.user.username, message], (err) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi database' });
        }
        logAction(db, req.user.username, 'send_message', null, { message });
        res.json({ success: true, message: 'Tin nhắn đã gửi' });
    });
});

// API change password (self)
app.put('/admin/change-password', authenticateAdmin, (req, res) => {
    const { old_password, new_password } = req.body;
    
    if (!old_password || !new_password) {
        return res.status(400).json({ error: 'Thiếu old_password hoặc new_password' });
    }
    
    db.get('SELECT password FROM admin WHERE username = ?', [req.user.username], (err, row) => {
        if (err || !row) {
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        bcrypt.compare(old_password, row.password, (err, result) => {
            if (err || !result) {
                return res.status(401).json({ error: 'Password cũ không đúng' });
            }
            
            bcrypt.hash(new_password, 10, (err, hash) => {
                if (err) {
                    return res.status(500).json({ error: 'Lỗi server' });
                }
                
                db.run('UPDATE admin SET password = ? WHERE username = ?', [hash, req.user.username], (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Lỗi database' });
                    }
                    logAction(db, req.user.username, 'change_password');
                    res.json({ success: true, message: 'Đổi password thành công' });
                });
            });
        });
    });
});

// API reset password (owner only, for others)
app.put('/admin/reset-password', authenticateOwner, (req, res) => {
    const { username, new_password } = req.body;
    
    if (!username || !new_password) {
        return res.status(400).json({ error: 'Thiếu username hoặc new_password' });
    }
    
    db.get('SELECT role FROM admin WHERE username = ?', [username], (err, row) => {
        if (err || !row) {
            return res.status(404).json({ error: 'Admin không tồn tại' });
        }
        
        if (row.role === 2) {
            return res.status(403).json({ error: 'Không thể reset password của owner khác' });
        }
        
        bcrypt.hash(new_password, 10, (err, hash) => {
            if (err) {
                return res.status(500).json({ error: 'Lỗi server' });
            }
            
            db.run('UPDATE admin SET password = ? WHERE username = ?', [hash, username], (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Lỗi database' });
                }
                logAction(db, req.user.username, 'reset_password', username);
                res.json({ success: true, message: `Đã reset password cho ${username}` });
            });
        });
    });
});

// API key info
app.get('/key-info/:key', (req, res) => {
    const { key } = req.params;
    
    db.get('SELECT * FROM keys WHERE key = ?', [key], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi database' });
        }
        
        if (!row) {
            return res.json({ exists: false, message: 'Key không tồn tại' });
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
            verified_at: row.verified_at,
            used: row.used === 1,
            banned: row.banned === 1,
            permanent: row.permanent === 1,
            is_expired: isExpired && !row.permanent
        });
    });
});

// API check time left
app.post('/check-time-left', (req, res) => {
    try {
        const { hwid } = req.body;
        
        if (!hwid) {
            return res.status(400).json({ success: false, message: 'Thiếu HWID' });
        }
        
        db.get('SELECT * FROM requests WHERE hwid = ?', [hwid], (err, row) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Lỗi server' });
            }
            
            if (!row) {
                return res.json({ can_request: true, time_left: 0, message: 'Bạn có thể lấy key ngay bây giờ' });
            }
            
            const lastRequestTime = new Date(row.last_request_time);
            const now = new Date();
            const timeDiff = now - lastRequestTime;
            const hoursDiff = timeDiff / (1000 * 60 * 60);
            
            if (hoursDiff >= 1) {
                return res.json({ can_request: true, time_left: 0, message: 'Bạn có thể lấy key ngay bây giờ' });
            } else {
                const timeLeft = 1 - hoursDiff;
                const hoursLeft = Math.floor(timeLeft);
                const minutesLeft = Math.floor((timeLeft - hoursLeft) * 60);
                return res.json({ can_request: false, time_left: timeLeft, message: `Bạn phải chờ ${hoursLeft} giờ ${minutesLeft} phút nữa để lấy key mới` });
            }
        });
    } catch (error) {
        console.error('Error in /check-time-left:', error);
        res.status(500).json({ success: false, message: 'Lỗi server nội bộ' });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString(), service: 'Key System API', database_path: dbPath });
});

// Admin login
app.post('/admin/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Thiếu username hoặc password' });
    }
    
    db.get('SELECT * FROM admin WHERE username = ?', [username], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi server' });
        }
        
        if (!row) {
            return res.status(401).json({ error: 'Sai thông tin đăng nhập' });
        }
        
        bcrypt.compare(password, row.password, (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Lỗi server' });
            }
            
            if (result) {
                const token = jwt.sign({ username: row.username, role: row.role }, SECRET_KEY, { expiresIn: '1h' });
                res.json({ success: true, token, role: row.role, message: 'Đăng nhập thành công' });
            } else {
                res.status(401).json({ error: 'Sai thông tin đăng nhập' });
            }
        });
    });
});

// API backup database (admin+)
app.get('/admin/backup', authenticateAdmin, (req, res) => {
    const backupPath = path.join(dataDir, `backup-${Date.now()}.db`);
    
    fs.copyFile(dbPath, backupPath, (err) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi khi tạo backup' });
        }
        logAction(db, req.user.username, 'backup_database', backupPath);
        res.json({ success: true, message: 'Backup thành công', backup_path: backupPath });
    });
});

// Root
app.get('/', (req, res) => {
    res.json({ 
        message: 'Key System API đang hoạt động',
        database: dbPath,
        // ... (update endpoints list if needed)
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server đang chạy trên port ${PORT}`);
    console.log(`💾 Database được lưu tại: ${dbPath}`);
});
