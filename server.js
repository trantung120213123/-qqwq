const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Biến môi trường (có thể đặt trong file .env)
const TOKEN_TTL_SECONDS = process.env.TOKEN_TTL_SECONDS || 300; // 5 phút
const KEY_TTL_SECONDS = process.env.KEY_TTL_SECONDS || 86400; // 24 giờ
const HWID_COOLDOWN_SECONDS = process.env.HWID_COOLDOWN_SECONDS || 3600; // 1 giờ
const HWID_HMAC_SECRET = process.env.HWID_HMAC_SECRET || 'some_long_random_secret_change_in_production';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'supersecret_admin_token_change_me';
const MAX_REQUESTS_PER_IP_PER_MIN = process.env.RATE_LIMIT || 10;

// Middleware
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 phút
  max: MAX_REQUESTS_PER_IP_PER_MIN,
  message: { error: 'Quá nhiều yêu cầu, vui lòng thử lại sau' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Khởi tạo database
const db = new sqlite3.Database('./keys.db', (err) => {
  if (err) {
    console.error('Lỗi kết nối database:', err);
  } else {
    console.log('Kết nối SQLite thành công');
    db.run('PRAGMA foreign_keys = ON'); // Bật foreign key constraints
  }
});

// Tạo các bảng cần thiết
db.serialize(() => {
  // Bảng tokens
  db.run(`CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    hwid_hash TEXT NOT NULL,
    ip_address TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER DEFAULT 0,
    used_at INTEGER
  )`);

  // Bảng keys
  db.run(`CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_value TEXT NOT NULL UNIQUE,
    hwid_hash TEXT,
    ip_address TEXT,
    token_id INTEGER,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    active INTEGER DEFAULT 1,
    used INTEGER DEFAULT 0,
    FOREIGN KEY(token_id) REFERENCES tokens(id)
  )`);

  // Bảng requests
  db.run(`CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hwid_hash TEXT NOT NULL UNIQUE,
    last_request_at INTEGER NOT NULL,
    request_count INTEGER DEFAULT 1,
    ip_address TEXT
  )`);

  // Bảng bans
  db.run(`CREATE TABLE IF NOT EXISTS bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hwid_hash TEXT,
    ip_address TEXT,
    reason TEXT,
    created_at INTEGER NOT NULL
  )`);

  // Tạo indexes
  db.run('CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens(token)');
  db.run('CREATE INDEX IF NOT EXISTS idx_keys_keyvalue ON keys(key_value)');
  db.run('CREATE INDEX IF NOT EXISTS idx_requests_hwid ON requests(hwid_hash)');
});

// Helper functions
function hashHwid(hwid) {
  return crypto.createHmac('sha256', HWID_HMAC_SECRET).update(hwid).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function generateKey() {
  return crypto.randomBytes(16).toString('hex').toUpperCase();
}

function isBanned(hwidHash, ip, callback) {
  db.get(
    'SELECT * FROM bans WHERE hwid_hash = ? OR ip_address = ?',
    [hwidHash, ip],
    (err, row) => {
      if (err) {
        console.error('Database error in isBanned:', err);
        return callback(err, false);
      }
      callback(null, !!row);
    }
  );
}

// API request token
app.post('/request-token', (req, res) => {
  try {
    const { hwid } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    
    if (!hwid) {
      return res.status(400).json({ error: 'Thiếu HWID' });
    }
    
    const hwidHash = hashHwid(hwid);
    const now = Math.floor(Date.now() / 1000);
    
    // Kiểm tra xem HWID hoặc IP có bị ban không
    isBanned(hwidHash, ip, (err, banned) => {
      if (err) {
        return res.status(500).json({ error: 'Lỗi server' });
      }
      
      if (banned) {
        return res.status(403).json({ error: 'Bị cấm truy cập' });
      }
      
      // Kiểm tra cooldown
      db.get(
        'SELECT * FROM requests WHERE hwid_hash = ?',
        [hwidHash],
        (err, row) => {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Lỗi server' });
          }
          
          if (row) {
            const timeDiff = now - row.last_request_at;
            if (timeDiff < HWID_COOLDOWN_SECONDS) {
              const timeLeft = HWID_COOLDOWN_SECONDS - timeDiff;
              return res.status(429).json({ 
                error: 'Vui lòng chờ', 
                time_left_seconds: timeLeft,
                message: `Bạn phải chờ ${Math.ceil(timeLeft/60)} phút nữa để yêu cầu token mới`
              });
            }
            
            // Cập nhật thời gian request
            db.run(
              'UPDATE requests SET last_request_at = ?, request_count = request_count + 1, ip_address = ? WHERE hwid_hash = ?',
              [now, ip, hwidHash],
              (err) => {
                if (err) console.error('Update request error:', err);
              }
            );
          } else {
            // Thêm request mới
            db.run(
              'INSERT INTO requests (hwid_hash, last_request_at, ip_address) VALUES (?, ?, ?)',
              [hwidHash, now, ip],
              (err) => {
                if (err) console.error('Insert request error:', err);
              }
            );
          }
          
          // Tạo token mới
          const token = generateToken();
          const expiresAt = now + TOKEN_TTL_SECONDS;
          
          db.run(
            'INSERT INTO tokens (token, hwid_hash, ip_address, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
            [token, hwidHash, ip, now, expiresAt],
            function(err) {
              if (err) {
                console.error('Insert token error:', err);
                return res.status(500).json({ error: 'Lỗi khi tạo token' });
              }
              
              const link = `${req.protocol}://${req.get('host')}/go/${token}`;
              res.json({ 
                success: true, 
                token, 
                link, 
                expires_at: expiresAt,
                message: 'Token đã được tạo thành công'
              });
            }
          );
        }
      );
    });
  } catch (error) {
    console.error('Error in /request-token:', error);
    res.status(500).json({ error: 'Lỗi server nội bộ' });
  }
});

// API redirect đến trang vượt link
app.get('/go/:token', (req, res) => {
  const { token } = req.params;
  const now = Math.floor(Date.now() / 1000);
  
  db.get(
    'SELECT * FROM tokens WHERE token = ? AND expires_at >= ? AND used = 0',
    [token, now],
    (err, row) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).send('Lỗi server');
      }
      
      if (!row) {
        return res.status(400).send('Token không hợp lệ hoặc đã hết hạn');
      }
      
      // Ở đây bạn có thể redirect đến trang quảng cáo (Linkvertise, v.v.)
      // Sau đó redirect về /final-getkey?token=xxx
      
      // Tạm thời redirect thẳng đến final-getkey (cho mục đích demo)
      res.redirect(`/final-getkey?token=${token}`);
    }
  );
});

// Trang sau khi vượt link thành công
app.get('/final-getkey', (req, res) => {
  const { token } = req.query;
  const now = Math.floor(Date.now() / 1000);
  
  if (!token) {
    return res.status(400).send('Thiếu token');
  }
  
  db.get(
    'SELECT * FROM tokens WHERE token = ? AND expires_at >= ? AND used = 0',
    [token, now],
    (err, row) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).send('Lỗi server');
      }
      
      if (!row) {
        return res.status(400).send('Token không hợp lệ hoặc đã hết hạn');
      }
      
      // Trả về trang HTML với script tự động gọi API /get-key
      res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Xác minh thành công</title>
          <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            .success { color: green; font-size: 24px; }
            .loading { color: #666; margin-top: 20px; }
          </style>
        </head>
        <body>
          <div class="success">✓ Xác minh thành công!</div>
          <div class="loading" id="status">Đang tạo key, vui lòng chờ...</div>
          
          <script>
            // Lấy HWID từ localStorage hoặc tạo mới
            function generateHWID() {
              const components = [
                navigator.userAgent,
                navigator.platform,
                navigator.hardwareConcurrency,
                screen.width + 'x' + screen.height,
                navigator.language,
                new Date().getTimezoneOffset()
              ];
              let hwid = components.join('|');
              let hash = 0;
              for (let i = 0; i < hwid.length; i++) {
                const char = hwid.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash;
              }
              return 'hwid_' + Math.abs(hash).toString(16);
            }
            
            const hwid = generateHWID();
            const token = '${token}';
            
            // Gọi API để lấy key
            fetch('/get-key', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ token, hwid })
            })
            .then(response => response.json())
            .then(data => {
              if (data.success) {
                document.getElementById('status').innerHTML = 
                  'Key của bạn: <strong>' + data.key + '</strong><br>' +
                  'Hết hạn: ' + new Date(data.expires_at * 1000).toLocaleString('vi-VN');
                
                // Tự động copy key vào clipboard
                navigator.clipboard.writeText(data.key).then(() => {
                  document.getElementById('status').innerHTML += 
                    '<br><br>✓ Đã sao chép key vào clipboard!';
                });
              } else {
                document.getElementById('status').innerHTML = 
                  'Lỗi: ' + (data.error || data.message);
              }
            })
            .catch(error => {
              document.getElementById('status').innerHTML = 
                'Lỗi kết nối: ' + error.message;
            });
          </script>
        </body>
        </html>
      `);
    }
  );
});

// API lấy key sau khi vượt link
app.post('/get-key', (req, res) => {
  try {
    const { token, hwid } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    
    if (!token || !hwid) {
      return res.status(400).json({ error: 'Thiếu token hoặc HWID' });
    }
    
    const hwidHash = hashHwid(hwid);
    const now = Math.floor(Date.now() / 1000);
    
    // Kiểm tra xem HWID hoặc IP có bị ban không
    isBanned(hwidHash, ip, (err, banned) => {
      if (err) {
        return res.status(500).json({ error: 'Lỗi server' });
      }
      
      if (banned) {
        return res.status(403).json({ error: 'Bị cấm truy cập' });
      }
      
      // Sử dụng transaction để đảm bảo tính atomic
      db.serialize(() => {
        db.run('BEGIN IMMEDIATE');
        
        db.get(
          'SELECT * FROM tokens WHERE token = ? AND expires_at >= ? AND used = 0',
          [token, now],
          (err, tokenRow) => {
            if (err) {
              db.run('ROLLBACK');
              console.error('Database error:', err);
              return res.status(500).json({ error: 'Lỗi server' });
            }
            
            if (!tokenRow) {
              db.run('ROLLBACK');
              return res.status(403).json({ error: 'Token không hợp lệ hoặc đã được sử dụng' });
            }
            
            // Kiểm tra HWID có khớp không
            if (tokenRow.hwid_hash !== hwidHash) {
              db.run('ROLLBACK');
              return res.status(403).json({ error: 'HWID không khớp với token' });
            }
            
            // Tạo key mới
            const keyValue = generateKey();
            const expiresAt = now + KEY_TTL_SECONDS;
            
            // Lưu key vào database
            db.run(
              'INSERT INTO keys (key_value, hwid_hash, ip_address, token_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
              [keyValue, hwidHash, ip, tokenRow.id, now, expiresAt],
              function(err) {
                if (err) {
                  db.run('ROLLBACK');
                  console.error('Insert key error:', err);
                  return res.status(500).json({ error: 'Lỗi khi tạo key' });
                }
                
                // Đánh dấu token đã sử dụng
                db.run(
                  'UPDATE tokens SET used = 1, used_at = ? WHERE id = ?',
                  [now, tokenRow.id],
                  function(err) {
                    if (err) {
                      db.run('ROLLBACK');
                      console.error('Update token error:', err);
                      return res.status(500).json({ error: 'Lỗi khi cập nhật token' });
                    }
                    
                    db.run('COMMIT');
                    res.json({ 
                      success: true, 
                      key: keyValue, 
                      expires_at: expiresAt,
                      message: 'Key đã được tạo thành công'
                    });
                  }
                );
              }
            );
          }
        );
      });
    });
  } catch (error) {
    console.error('Error in /get-key:', error);
    res.status(500).json({ error: 'Lỗi server nội bộ' });
  }
});

// API xác thực key (giữ nguyên từ hệ thống cũ)
app.post('/verify-key', (req, res) => {
  try {
    const { key, hwid } = req.body;
    
    if (!key) {
      return res.json({ valid: false, reason: 'Thiếu key' });
    }
    
    if (!hwid) {
      return res.json({ valid: false, reason: 'Thiếu HWID' });
    }
    
    const hwidHash = hashHwid(hwid);
    const now = Math.floor(Date.now() / 1000);
    
    db.get(
      'SELECT * FROM keys WHERE key_value = ? AND active = 1',
      [key],
      (err, row) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ valid: false, reason: 'Lỗi server' });
        }
        
        if (!row) {
          return res.json({ valid: false, reason: 'Key không tồn tại' });
        }
        
        // Kiểm tra hết hạn
        if (now > row.expires_at) {
          return res.json({ valid: false, reason: 'Key đã hết hạn' });
        }
        
        // Kiểm tra HWID nếu key được bind với HWID
        if (row.hwid_hash && row.hwid_hash !== hwidHash) {
          return res.json({ valid: false, reason: 'Key không khớp với thiết bị' });
        }
        
        res.json({ 
          valid: true,
          created_at: row.created_at,
          expires_at: row.expires_at
        });
      }
    );
  } catch (error) {
    console.error('Error in /verify-key:', error);
    res.status(500).json({ valid: false, reason: 'Lỗi server nội bộ' });
  }
});

// API kiểm tra thời gian chờ còn lại (giữ nguyên từ hệ thống cũ)
app.post('/check-time-left', (req, res) => {
  try {
    const { hwid } = req.body;
    
    if (!hwid) {
      return res.status(400).json({ error: 'Thiếu HWID' });
    }
    
    const hwidHash = hashHwid(hwid);
    const now = Math.floor(Date.now() / 1000);
    
    db.get(
      'SELECT * FROM requests WHERE hwid_hash = ?',
      [hwidHash],
      (err, row) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Lỗi server' });
        }
        
        if (!row) {
          return res.json({ can_request: true, time_left_seconds: 0 });
        }
        
        const timeDiff = now - row.last_request_at;
        if (timeDiff >= HWID_COOLDOWN_SECONDS) {
          return res.json({ can_request: true, time_left_seconds: 0 });
        } else {
          const timeLeft = HWID_COOLDOWN_SECONDS - timeDiff;
          return res.json({ 
            can_request: false, 
            time_left_seconds: timeLeft,
            message: `Bạn phải chờ ${Math.ceil(timeLeft/60)} phút nữa để yêu cầu token mới`
          });
        }
      }
    );
  } catch (error) {
    console.error('Error in /check-time-left:', error);
    res.status(500).json({ error: 'Lỗi server nội bộ' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'Key System API với token'
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'Key System API với token đang hoạt động',
    endpoints: {
      health: '/health',
      requestToken: 'POST /request-token',
      getKey: 'POST /get-key',
      verifyKey: 'POST /verify-key',
      checkTimeLeft: 'POST /check-time-left',
      goToken: 'GET /go/:token',
      finalGetKey: 'GET /final-getkey?token=xxx'
    }
  });
});

// Khởi động server
app.listen(PORT, () => {
  console.log(`🚀 Server đang chạy trên port ${PORT}`);
  console.log(`📝 Cấu hình hệ thống:`);
  console.log(`   - Token TTL: ${TOKEN_TTL_SECONDS} giây`);
  console.log(`   - Key TTL: ${KEY_TTL_SECONDS} giây`);
  console.log(`   - HWID Cooldown: ${HWID_COOLDOWN_SECONDS} giây`);
  console.log(`   - Rate Limit: ${MAX_REQUESTS_PER_IP_PER_MIN} requests/phút`);
});
