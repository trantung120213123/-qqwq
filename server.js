const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js'); // npm install @supabase/supabase-js
const path = require('path');
const bcrypt = require('bcrypt');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const http = require('http');
const { Server } = require('socket.io');
const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = 'tungdeptrai1202';
// Supabase config
const SUPABASE_URL = 'https://wxlxlhbfuezfvtbshwsw.supabase.co';
const SUPABASE_SERVICE_ROLE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Ind4bHhsaGJmdWV6ZnZ0YnNod3N3Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2MjIzODYzNiwiZXhwIjoyMDc3ODE0NjM2fQ.a9AoVbSciixxREtvQz31auD0hnMADdpit2HuzkShhMA';
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: {
        autoRefreshToken: false,
        persistSession: false
    }
});
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
// Khởi tạo database: Tạo bảng nếu chưa có (Supabase tự handle schema, nhưng có thể dùng RPC hoặc migration tool; ở đây giả sử schema đã tạo từ SQL trước)
async function initializeSupabase() {
    console.log('✅ Supabase client đã sẵn sàng. Giả sử schema đã được tạo từ SQL script trước đó.');
    
    // Thêm owner mặc định nếu chưa có
    const ownerPassword = 'tungdeptrai1202';
    const { data: existingOwner, error: checkError } = await supabase
        .from('admin')
        .select('username')
        .eq('username', 'owner')
        .single();
    if (checkError && checkError.code !== 'PGRST116') { // PGRST116: no rows
        console.error('Lỗi kiểm tra owner:', checkError);
        return;
    }
    if (!existingOwner) {
        const hash = await bcrypt.hash(ownerPassword, 10);
        const { error: insertError } = await supabase
            .from('admin')
            .insert({
                username: 'owner',
                password: hash,
                is_super_admin: true,
                is_owner: true
            });
        if (insertError) {
            console.error('Lỗi khi tạo owner mặc định:', insertError);
        } else {
            console.log('Owner mặc định đã được tạo. Username: owner, Password: tungdeptrai1202');
        }
    } else {
        console.log('Owner đã tồn tại, bỏ qua tạo mới.');
    }
}
// Gọi init khi start server
initializeSupabase().catch(console.error);
// Hàm ghi log hoạt động admin (async)
async function logAdminActivity(adminUsername, action, targetType = null, targetValue = null, details = null) {
    const { error } = await supabase
        .from('admin_activity')
        .insert({
            admin_username: adminUsername,
            action,
            target_type: targetType,
            target_value: targetValue,
            details
        });
    if (error) {
        console.error('Lỗi khi ghi log hoạt động admin:', error);
    }
}
// Hàm ghi log hoạt động key của user (async)
async function logUserKeyActivity(userId, key, action, details = null) {
    const { error } = await supabase
        .from('user_key_history')
        .insert({
            user_id: userId,
            key,
            action,
            details
        });
    if (error) {
        console.error('Lỗi khi ghi log hoạt động key của user:', error);
    }
}
// Hàm tạo key ngẫu nhiên
function generateRandomKey(length = 18, prefix = '') {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789'; // chữ thường + số
    let key = '';
    for (let i = 0; i < length; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return prefix + key;
}

// Hàm cập nhật thông tin user (async)
async function updateUserInfo(user_id, username) {
    if (!user_id) return;
    const { data: existingUser, error: checkError } = await supabase
        .from('users')
        .select('*')
        .eq('user_id', user_id)
        .single();
    if (checkError && checkError.code !== 'PGRST116') {
        console.error('Lỗi khi kiểm tra user:', checkError);
        return;
    }
    if (existingUser) {
        const { error: updateError } = await supabase
            .from('users')
            .update({
                username,
                last_seen: new Date().toISOString(),
                total_keys_used: existingUser.total_keys_used + 1
            })
            .eq('user_id', user_id);
        if (updateError) {
            console.error('Lỗi khi cập nhật user:', updateError);
        }
    } else {
        const { error: insertError } = await supabase
            .from('users')
            .insert({
                user_id,
                username
            });
        if (insertError) {
            console.error('Lỗi khi thêm user mới:', insertError);
        }
    }
}
// Hàm authenticateRole (giữ nguyên)
function authenticateRole(roles = []) {
    return async (req, res, next) => {
        let token = null;
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.substring(7);
        } else if (req.headers['x-access-token']) {
            token = req.headers['x-access-token'];
        } else if (req.query && req.query.token) {
            token = req.query.token;
        }
        if (!token) {
            return res.status(401).json({ error: 'Token không hợp lệ' });
        }
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
// Socket.IO authentication middleware (giữ nguyên, nhưng chat dùng Supabase async)
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
// Socket.IO chat handling (async Supabase)
io.on('connection', async (socket) => {
    const username = socket.user.username;
    console.log(`Admin ${username} connected to chat`);
    
    // Send chat history on connection
    const { data: rows, error } = await supabase
        .from('admin_chat')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(50);
    if (error) {
        console.error('Lỗi khi lấy lịch sử chat:', error);
        return;
    }
    socket.emit('history', rows.reverse());
    // Handle incoming messages
    socket.on('message', async (msg) => {
        if (!msg || typeof msg !== 'string' || msg.trim() === '') {
            socket.emit('error', { message: 'Tin nhắn không hợp lệ' });
            return;
        }
        const message = msg.trim();
        const { data: newMessage, error: insertError } = await supabase
            .from('admin_chat')
            .insert({
                admin_username: username,
                message
            })
            .select()
            .single();
        if (insertError) {
            console.error('Lỗi khi lưu tin nhắn:', insertError);
            socket.emit('error', { message: 'Lỗi khi lưu tin nhắn' });
            return;
        }
        const chatMessage = {
            id: newMessage.id,
            admin_username: username,
            message: message,
            created_at: new Date().toISOString()
        };
        // Broadcast message to all connected clients
        io.emit('message', chatMessage);
    });
    socket.on('disconnect', () => {
        console.log(`Admin ${username} disconnected from chat`);
    });
});
// API tạo key mới với kiểm tra HWID và thời gian 24h (async)
app.post('/get-key', async (req, res) => {
    try {
        const { hwid } = req.body;
      
        if (!hwid) {
            return res.status(400).json({
                success: false,
                message: 'Thiếu HWID'
            });
        }
      
        const now = new Date();
      
        const { data: row, error: selectError } = await supabase
            .from('requests')
            .select('*')
            .eq('hwid', hwid)
            .single();
        if (selectError && selectError.code !== 'PGRST116') {
            console.error('Database error:', selectError);
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
          
            const { error: updateError } = await supabase
                .from('requests')
                .update({
                    last_request_time: now.toISOString(),
                    request_count: row.request_count + 1
                })
                .eq('hwid', hwid);
            if (updateError) {
                console.error('Update request error:', updateError);
            }
        } else {
            const { error: insertError } = await supabase
                .from('requests')
                .insert({
                    hwid,
                    last_request_time: now.toISOString()
                });
            if (insertError) {
                console.error('Insert request error:', insertError);
            }
        }
      
        const newKey = generateRandomKey(5);
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
      
        const { data: insertedKey, error: insertKeyError } = await supabase
            .from('keys')
            .insert({
                key: newKey,
                hwid,
                expires_at: expiresAt.toISOString()
            })
            .select()
            .single();
        if (insertKeyError) {
            console.error('Insert key error:', insertKeyError);
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
    } catch (error) {
        console.error('Error in /get-key:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi server nội bộ'
        });
    }
});
// API xác thực key (async)
app.post('/verify-key', async (req, res) => {
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
      
        const { data: row, error: selectError } = await supabase
            .from('keys')
            .select('*')
            .eq('key', key)
            .single();
        if (selectError) {
            console.error('Database error:', selectError);
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
      
        await updateUserInfo(user_id, username);
        await logUserKeyActivity(user_id, key, 'verify', `Key verified by ${username}`);
      
        const { error: updateError } = await supabase
            .from('keys')
            .update({
                used: true,
                user_id,
                username
            })
            .eq('key', key);
        if (updateError) {
            console.error('Lỗi khi cập nhật key:', updateError);
        }
      
        res.json({
            valid: true,
            user_id: user_id,
            username: username,
            created_at: row.created_at,
            expires_at: row.expires_at,
            permanent: row.permanent
        });
    } catch (error) {
        console.error('Error in /verify-key:', error);
        res.status(500).json({
            valid: false,
            reason: 'Lỗi server nội bộ'
        });
    }
});
// API lấy danh sách tất cả keys (async)
app.get('/admin/keys', authenticateRole(['admin', 'super_admin', 'owner']), async (req, res) => {
    const { data: rows, error } = await supabase
        .from('keys')
        .select('*')
        .order('created_at', { ascending: false });
    if (error) {
        console.error('Database error:', error);
        return res.status(500).json({ error: 'Lỗi database: ' + error.message });
    }
  
    res.json(rows || []);
});
// API lấy danh sách tất cả users (async)
app.get('/admin/users', authenticateRole(['admin', 'super_admin', 'owner']), async (req, res) => {
    const { data: rows, error } = await supabase
        .from('users')
        .select('*')
        .order('last_seen', { ascending: false });
    if (error) {
        console.error('Database error:', error);
        return res.status(500).json({ error: 'Lỗi database: ' + error.message });
    }
  
    res.json(rows || []);
});
// API lấy danh sách admin (async)
app.get('/admin/admins', authenticateRole(['super_admin', 'owner']), async (req, res) => {
    const { data: rows, error } = await supabase
        .from('admin')
        .select('id, username, is_super_admin, is_owner, created_at')
        .order('created_at', { ascending: false });
    if (error) {
        console.error('Database error:', error);
        return res.status(500).json({ error: 'Lỗi database: ' + error.message });
    }
  
    res.json(rows || []);
});
// API lấy lịch sử hoạt động admin (async)
app.get('/admin/activity', authenticateRole(['owner']), async (req, res) => {
    const limit = parseInt(req.query.limit) || 100;
  
    const { data: rows, error } = await supabase
        .from('admin_activity')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(limit);
    if (error) {
        console.error('Database error:', error);
        return res.status(500).json({ error: 'Lỗi database: ' + error.message });
    }
  
    res.json(rows || []);
});
// API lấy lịch sử key của user (async)
app.get('/admin/user-key-history/:user_id', authenticateRole(['admin', 'super_admin', 'owner']), async (req, res) => {
    const { user_id } = req.params;
    const limit = parseInt(req.query.limit) || 50;
  
    const { data: rows, error } = await supabase
        .from('user_key_history')
        .select('*')
        .eq('user_id', user_id)
        .order('created_at', { ascending: false })
        .limit(limit);
    if (error) {
        console.error('Database error:', error);
        return res.status(500).json({ error: 'Lỗi database: ' + error.message });
    }
  
    res.json(rows || []);
});
// API ban user (async)
app.post('/admin/ban-user', authenticateRole(['admin', 'super_admin', 'owner']), async (req, res) => {
    const { user_id } = req.body;
    const admin_username = req.user.username;
  
    if (!user_id) {
        return res.status(400).json({ error: 'Thiếu user_id' });
    }
  
    const { error: keysError } = await supabase
        .from('keys')
        .update({ banned: true })
        .eq('user_id', user_id);
    if (keysError) {
        console.error('Database error:', keysError);
        return res.status(500).json({ error: 'Lỗi database: ' + keysError.message });
    }
  
    const { error: usersError } = await supabase
        .from('users')
        .update({ banned: true })
        .eq('user_id', user_id);
    if (usersError) {
        console.error('Database error:', usersError);
        return res.status(500).json({ error: 'Lỗi database: ' + usersError.message });
    }
  
    await logAdminActivity(admin_username, 'ban_user', 'user', user_id, `Banned user ${user_id}`);
  
    // Lấy số changes (Supabase không có this.changes, dùng count)
    const { count: changes, error: countError } = await supabase
        .from('users')
        .select('*', { count: 'exact', head: true })
        .eq('user_id', user_id); // Thay bằng count affected nếu cần, nhưng đơn giản dùng 1
    if (countError) {
        console.error('Count error:', countError);
        changes = 1; // Fallback
    }
  
    res.json({
        success: true,
        message: `Đã ban user ${user_id}`,
        changes: changes || 1
    });
});
// API unban user (async) - Tương tự ban, chỉ đổi FALSE
app.post('/admin/unban-user', authenticateRole(['admin', 'super_admin', 'owner']), async (req, res) => {
    const { user_id } = req.body;
    const admin_username = req.user.username;
  
    if (!user_id) {
        return res.status(400).json({ error: 'Thiếu user_id' });
    }
  
    const { error: keysError } = await supabase
        .from('keys')
        .update({ banned: false })
        .eq('user_id', user_id);
    if (keysError) {
        console.error('Database error:', keysError);
        return res.status(500).json({ error: 'Lỗi database: ' + keysError.message });
    }
  
    const { error: usersError } = await supabase
        .from('users')
        .update({ banned: false })
        .eq('user_id', user_id);
    if (usersError) {
        console.error('Database error:', usersError);
        return res.status(500).json({ error: 'Lỗi database: ' + usersError.message });
    }
  
    await logAdminActivity(admin_username, 'unban_user', 'user', user_id, `Unbanned user ${user_id}`);
  
    res.json({
        success: true,
        message: `Đã unban user ${user_id}`,
        changes: 1 // Fallback
    });
});
// API chỉnh sửa thời gian key (async)
app.post('/admin/update-key-expiry', authenticateRole(['admin', 'super_admin', 'owner']), async (req, res) => {
    const { key, hours, permanent } = req.body;
    const admin_username = req.user.username;
  
    if (!key) {
        return res.status(400).json({ error: 'Thiếu key' });
    }
  
    let updateData = {};
    if (permanent) {
        updateData = { permanent: true, expires_at: null };
        const { error } = await supabase
            .from('keys')
            .update(updateData)
            .eq('key', key);
        if (error) {
            console.error('Database error:', error);
            return res.status(500).json({ error: 'Lỗi database: ' + error.message });
        }
        // Check if updated
        const { data: updatedRow } = await supabase
            .from('keys')
            .select('key')
            .eq('key', key)
            .single();
        if (!updatedRow) {
            return res.status(404).json({ error: 'Key không tồn tại' });
        }
      
        await logAdminActivity(admin_username, 'update_key', 'key', key, 'Set key to permanent');
      
        return res.json({
            success: true,
            message: `Đã đặt key ${key} thành vĩnh viễn`,
            permanent: true
        });
    } else if (hours) {
        const newExpiry = new Date(Date.now() + hours * 60 * 60 * 1000);
        updateData = { expires_at: newExpiry.toISOString(), permanent: false };
      
        const { error } = await supabase
            .from('keys')
            .update(updateData)
            .eq('key', key);
        if (error) {
            console.error('Database error:', error);
            return res.status(500).json({ error: 'Lỗi database: ' + error.message });
        }
        const { data: updatedRow } = await supabase
            .from('keys')
            .select('key')
            .eq('key', key)
            .single();
        if (!updatedRow) {
            return res.status(404).json({ error: 'Key không tồn tại' });
        }
      
        await logAdminActivity(admin_username, 'update_key', 'key', key, `Set key expiry to ${hours} hours`);
      
        res.json({
            success: true,
            message: `Đã cập nhật thời gian key ${key} thành ${hours} giờ`,
            new_expiry: newExpiry.toISOString(),
            permanent: false
        });
    } else {
        return res.status(400).json({ error: 'Thiếu hours hoặc permanent' });
    }
});
// API tạo key mới (async)
app.post('/admin/create-key', authenticateRole(['admin', 'super_admin', 'owner']), async (req, res) => {
    const { hours = 24, permanent = false, keyPrefix = 'key-' } = req.body;
    const admin_username = req.user.username;
  
    if (typeof keyPrefix !== 'string' || keyPrefix.trim() === '') {
        return res.status(400).json({ error: 'keyPrefix phải là chuỗi không rỗng' });
    }
    const safePrefix = keyPrefix.trim();
    const newKey = generateRandomKey(5, safePrefix);
    let expiresAt = null;
  
    if (!permanent) {
        expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
    }
  
    const { data: insertedKey, error } = await supabase
        .from('keys')
        .insert({
            key: newKey,
            expires_at: expiresAt,
            permanent
        })
        .select()
        .single();
    if (error) {
        console.error('Database error:', error);
        return res.status(500).json({ error: 'Lỗi khi tạo key' });
    }
  
    await logAdminActivity(admin_username, 'create_key', 'key', newKey, `Created ${permanent ? 'permanent' : hours + ' hours'} key`);
  
    res.json({
        success: true,
        key: newKey,
        expires: expiresAt,
        permanent: permanent,
        message: 'Key đã được tạo thành công'
    });
});
// API xóa key (async)
app.delete('/admin/delete-key/:key', authenticateRole(['admin', 'super_admin', 'owner']), async (req, res) => {
    const { key } = req.params;
    const admin_username = req.user.username;
  
    const { error, count } = await supabase
        .from('keys')
        .delete()
        .eq('key', key)
        .select('key', { count: 'exact', head: true });
    if (error) {
        console.error('Database error:', error);
        return res.status(500).json({ error: 'Lỗi database: ' + error.message });
    }
  
    if (count === 0) {
        return res.status(404).json({ error: 'Key không tồn tại' });
    }
  
    await logAdminActivity(admin_username, 'delete_key', 'key', key, 'Deleted key');
  
    res.json({
        success: true,
        message: `Đã xóa key ${key}`
    });
});
// API tạo admin mới (async)
app.post('/admin/create-admin', authenticateRole(['super_admin', 'owner']), async (req, res) => {
    const { username, password } = req.body;
    const admin_username = req.user.username;
  
    if (!username || !password) {
        return res.status(400).json({ error: 'Thiếu username hoặc password' });
    }
  
    const { data: existingAdmin, error: checkError } = await supabase
        .from('admin')
        .select('*')
        .eq('username', username)
        .single();
    if (checkError && checkError.code !== 'PGRST116') {
        console.error('Database error:', checkError);
        return res.status(500).json({ error: 'Lỗi database: ' + checkError.message });
    }
  
    if (existingAdmin) {
        return res.status(400).json({ error: 'Admin đã tồn tại' });
    }
  
    const hash = await bcrypt.hash(password, 10);
    const { error: insertError } = await supabase
        .from('admin')
        .insert({
            username,
            password: hash
        });
    if (insertError) {
        console.error('Database error:', insertError);
        return res.status(500).json({ error: 'Lỗi khi tạo admin' });
    }
  
    await logAdminActivity(admin_username, 'create_admin', 'admin', username, 'Created new admin');
  
    res.json({
        success: true,
        message: `Đã tạo admin ${username} thành công`
    });
});
// API xóa admin (async)
app.delete('/admin/delete-admin/:username', authenticateRole(['owner']), async (req, res) => {
    const { username } = req.params;
    const admin_username = req.user.username;
  
    if (username === 'owner') {
        return res.status(400).json({ error: 'Không thể xóa owner' });
    }
  
    const { error, count } = await supabase
        .from('admin')
        .delete()
        .eq('username', username)
        .select('username', { count: 'exact', head: true });
    if (error) {
        console.error('Database error:', error);
        return res.status(500).json({ error: 'Lỗi database: ' + error.message });
    }
  
    if (count === 0) {
        return res.status(404).json({ error: 'Admin không tồn tại' });
    }
  
    await logAdminActivity(admin_username, 'delete_admin', 'admin', username, 'Deleted admin');
  
    res.json({
        success: true,
        message: `Đã xóa admin ${username}`
    });
});
// API cập nhật quyền admin (async)
app.post('/admin/update-admin-role', authenticateRole(['owner']), async (req, res) => {
    const { username, is_super_admin } = req.body;
    const admin_username = req.user.username;
  
    if (!username) {
        return res.status(400).json({ error: 'Thiếu username' });
    }
  
    if (username === 'owner') {
        return res.status(400).json({ error: 'Không thể thay đổi quyền owner' });
    }
  
    const { error, count } = await supabase
        .from('admin')
        .update({ is_super_admin })
        .eq('username', username)
        .select('username', { count: 'exact', head: true });
    if (error) {
        console.error('Database error:', error);
        return res.status(500).json({ error: 'Lỗi database: ' + error.message });
    }
  
    if (count === 0) {
        return res.status(404).json({ error: 'Admin không tồn tại' });
    }
  
    const action = is_super_admin ? 'promote_admin' : 'demote_admin';
    await logAdminActivity(admin_username, action, 'admin', username,
                          `${is_super_admin ? 'Promoted to' : 'Demoted from'} super admin`);
  
    res.json({
        success: true,
        message: `Đã ${is_super_admin ? 'thăng cấp' : 'hạ cấp'} admin ${username}`
    });
});
// API kiểm tra key info (async)
app.get('/key-info/:key', async (req, res) => {
    const { key } = req.params;
  
    const { data: row, error } = await supabase
        .from('keys')
        .select('*')
        .eq('key', key)
        .single();
    if (error) {
        return res.status(500).json({
            error: 'Lỗi database: ' + error.message
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
        used: row.used,
        banned: row.banned,
        permanent: row.permanent,
        is_expired: isExpired && !row.permanent
    });
});
// API kiểm tra thời gian chờ còn lại theo HWID (async)
app.post('/check-time-left', async (req, res) => {
    try {
        const { hwid } = req.body;
      
        if (!hwid) {
            return res.status(400).json({
                success: false,
                message: 'Thiếu HWID'
            });
        }
      
        const { data: row, error: selectError } = await supabase
            .from('requests')
            .select('*')
            .eq('hwid', hwid)
            .single();
        if (selectError && selectError.code !== 'PGRST116') {
            console.error('Database error:', selectError);
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
        database: 'Supabase',
        url: SUPABASE_URL
    });
});
// Admin login endpoint (async, với bypass cho owner)
app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;
  
    if (!username || !password) {
        return res.status(400).json({ error: 'Thiếu username hoặc password' });
    }
  
    if (username === 'owner') {
        // Bypass database cho owner: Hardcode check password
        if (password === 'tungdeptrai1202') {
            const token = jwt.sign({
                username: 'owner',
                is_super_admin: true, // Owner luôn có quyền super_admin
                is_owner: true
            }, SECRET, { expiresIn: '1d' });
      
            return res.json({
                success: true,
                token,
                is_super_admin: true,
                is_owner: true,
                message: 'Đăng nhập thành công (owner bypass)'
            });
        } else {
            return res.status(401).json({ error: 'Sai thông tin đăng nhập' });
        }
    } else {
        // Đối với admin khác: Vẫn dùng database như cũ
        const { data: row, error } = await supabase
            .from('admin')
            .select('*')
            .eq('username', username)
            .single();
        if (error) {
            console.error('Database error:', error);
            return res.status(500).json({ error: 'Lỗi server' });
        }
  
        if (!row) {
            return res.status(401).json({ error: 'Sai thông tin đăng nhập' });
        }
  
        const result = await bcrypt.compare(password, row.password);
  
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
    }
});
// API backup: Với Supabase, dùng export data hoặc skip (ở đây log info)
app.get('/admin/backup', authenticateRole(['admin', 'super_admin', 'owner']), async (req, res) => {
    // Supabase không có direct backup như file, gợi ý dùng Supabase dashboard hoặc pg_dump
    res.json({
        success: true,
        message: 'Backup: Sử dụng Supabase dashboard hoặc pg_dump cho export. Không hỗ trợ file backup trực tiếp.',
        guide: 'https://supabase.com/docs/guides/database/backups'
    });
});
// Root endpoint
app.get('/', (req, res) => {
    res.json({
        message: 'Key System API đang hoạt động với Supabase!',
        database: 'Supabase',
        url: SUPABASE_URL,
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
// API verify token (giữ nguyên)
app.post('/admin/verify-token', (req, res) => {
    const token = req.headers.authorization?.substring(7) || req.headers['x-access-token'] || req.query.token;
    if (!token) {
        return res.status(401).json({ error: 'Token không hợp lệ' });
    }
    try {
        const decoded = jwt.verify(token, SECRET);
        res.json({
            success: true,
            username: decoded.username,
            is_super_admin: decoded.is_super_admin,
            is_owner: decoded.is_owner
        });
    } catch (err) {
        res.status(401).json({ error: 'Token không hợp lệ hoặc đã hết hạn' });
    }
});
// API refresh token (giữ nguyên)
app.post('/admin/refresh-token', (req, res) => {
    const token = req.headers.authorization?.substring(7) || req.headers['x-access-token'] || req.query.token;
    try {
        const decoded = jwt.verify(token, SECRET, { ignoreExpiration: true });
        const newToken = jwt.sign(
            {
                username: decoded.username,
                is_super_admin: decoded.is_super_admin,
                is_owner: decoded.is_owner
            },
            SECRET,
            { expiresIn: '1d' }
        );
        res.json({ success: true, token: newToken });
    } catch (err) {
        res.status(401).json({ error: 'Token không hợp lệ' });
    }
});
// Khởi động server
server.listen(PORT, () => {
    console.log(`🚀 Server đang chạy trên port ${PORT}`);
    console.log(`☁️ Supabase URL: ${SUPABASE_URL}`);
    console.log(`🔑 Service Role Key: ${SUPABASE_SERVICE_ROLE_KEY.substring(0, 20)}... (đã load thành công)`);
});
