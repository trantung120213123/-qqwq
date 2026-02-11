const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js'); // npm install @supabase/supabase-js
const path = require('path');
const bcrypt = require('bcrypt');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const http = require('http');
const { Server } = require('socket.io');
const WebSocket = require('ws');
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
const blackFlashWsServer = new WebSocket.Server({ noServer: true });
const robloxChatWsServer = new WebSocket.Server({ noServer: true });

server.on('upgrade', (request, socket, head) => {
    if (!request.url) {
        socket.destroy();
        return;
    }
    if (request.url.startsWith('/blackflash-ws')) {
        blackFlashWsServer.handleUpgrade(request, socket, head, (ws) => {
            blackFlashWsServer.emit('connection', ws, request);
        });
        return;
    }
    if (request.url.startsWith('/chat-ws')) {
        robloxChatWsServer.handleUpgrade(request, socket, head, (ws) => {
            robloxChatWsServer.emit('connection', ws, request);
        });
        return;
    }
    socket.destroy();
});

const blackFlashSessions = new Map();
const blackFlashSockets = new Map();
const BLACKFLASH_TTL_MS = 15 * 60 * 1000;
const chatMemoryHistoryByServer = new Map();
const chatClients = new Set();
const MAX_CHAT_HISTORY = 500;
const privateChatRooms = new Map();
const PRIVATE_ROOM_TTL_MS = 2 * 60 * 60 * 1000;

function nowMs() {
    return Date.now();
}

function createBlackFlashId() {
    return `bf_${Math.random().toString(36).slice(2, 10)}_${Date.now().toString(36)}`;
}

function cleanupBlackFlashSessions() {
    const current = nowMs();
    for (const [id, session] of blackFlashSessions.entries()) {
        if (!session || (current - (session.updatedAt || current)) > BLACKFLASH_TTL_MS) {
            blackFlashSessions.delete(id);
        }
    }
}
function blackFlashPlayerKey(serverId, player) {
    return `${serverId}:${player}`;
}

function sendBlackFlashWs(ws, payload) {
    try {
        if (!ws || ws.readyState !== WebSocket.OPEN) return;
        ws.send(JSON.stringify(payload));
    } catch (_) {}
}

function notifyBlackFlashPlayer(serverId, player, payload) {
    const key = blackFlashPlayerKey(serverId, player);
    const ws = blackFlashSockets.get(key);
    if (ws) {
        sendBlackFlashWs(ws, payload);
    }
}

function broadcastBlackFlashSession(session, payload) {
    if (!session) return;
    notifyBlackFlashPlayer(session.serverId, session.sender, payload);
    notifyBlackFlashPlayer(session.serverId, session.receiver, payload);
}

blackFlashWsServer.on('connection', (ws) => {
    let currentServerId = null;
    let currentPlayer = null;

    sendBlackFlashWs(ws, { type: 'connected' });

    ws.on('message', (raw) => {
        try {
            cleanupBlackFlashSessions();
            const msg = JSON.parse(raw.toString());
            const type = msg && msg.type;

            if (type === 'register') {
                const { serverId, player } = msg;
                if (!serverId || !player) {
                    sendBlackFlashWs(ws, { type: 'error', message: 'missing register data' });
                    return;
                }
                currentServerId = serverId;
                currentPlayer = player;
                blackFlashSockets.set(blackFlashPlayerKey(serverId, player), ws);
                sendBlackFlashWs(ws, { type: 'registered', serverId, player });
                return;
            }

            if (!currentServerId || !currentPlayer) {
                sendBlackFlashWs(ws, { type: 'error', message: 'not registered' });
                return;
            }

            if (type === 'invite') {
                const { sender, receiver, placeId } = msg;
                if (!sender || !receiver || sender === receiver) {
                    sendBlackFlashWs(ws, { type: 'error', message: 'invalid invite' });
                    return;
                }

                let session = null;
                for (const item of blackFlashSessions.values()) {
                    const samePair = item.serverId === currentServerId &&
                        ((item.sender === sender && item.receiver === receiver) ||
                        (item.sender === receiver && item.receiver === sender));
                    const active = ['pending', 'accepted', 'started'].includes(item.status);
                    if (samePair && active) {
                        session = item;
                        break;
                    }
                }
                if (!session) {
                    const id = createBlackFlashId();
                    session = {
                        id,
                        sender,
                        receiver,
                        serverId: currentServerId,
                        placeId: placeId || null,
                        status: 'pending',
                        senderReady: false,
                        receiverReady: false,
                        createdAt: nowMs(),
                        updatedAt: nowMs()
                    };
                    blackFlashSessions.set(id, session);
                } else {
                    session.updatedAt = nowMs();
                }

                notifyBlackFlashPlayer(currentServerId, sender, {
                    type: 'invite_sent',
                    inviteId: session.id,
                    receiver: session.receiver,
                    status: session.status
                });
                notifyBlackFlashPlayer(currentServerId, receiver, {
                    type: 'incoming_invite',
                    inviteId: session.id,
                    sender: session.sender,
                    receiver: session.receiver
                });
                return;
            }

            if (type === 'respond') {
                const { inviteId, player, accepted } = msg;
                const session = blackFlashSessions.get(inviteId);
                if (!session || session.serverId !== currentServerId) {
                    sendBlackFlashWs(ws, { type: 'error', message: 'session not found' });
                    return;
                }
                if (player !== session.receiver && player !== session.sender) {
                    sendBlackFlashWs(ws, { type: 'error', message: 'forbidden' });
                    return;
                }

                if (!accepted) {
                    session.status = 'rejected';
                    session.updatedAt = nowMs();
                    broadcastBlackFlashSession(session, {
                        type: 'invite_rejected',
                        inviteId: session.id,
                        by: player
                    });
                    return;
                }

                session.status = 'accepted';
                session.updatedAt = nowMs();
                broadcastBlackFlashSession(session, {
                    type: 'invite_accepted',
                    inviteId: session.id,
                    sender: session.sender,
                    receiver: session.receiver
                });
                return;
            }

            if (type === 'start') {
                const { inviteId, player, role, ready } = msg;
                const session = blackFlashSessions.get(inviteId);
                if (!session || session.serverId !== currentServerId) {
                    sendBlackFlashWs(ws, { type: 'error', message: 'session not found' });
                    return;
                }
                const setReady = ready !== false;
                if (player === session.sender || role === 'sender') {
                    session.senderReady = setReady;
                } else if (player === session.receiver || role === 'receiver') {
                    session.receiverReady = setReady;
                } else {
                    sendBlackFlashWs(ws, { type: 'error', message: 'forbidden' });
                    return;
                }

                session.status = (session.senderReady && session.receiverReady) ? 'started' : 'accepted';
                session.updatedAt = nowMs();

                broadcastBlackFlashSession(session, {
                    type: 'ready_update',
                    inviteId: session.id,
                    status: session.status,
                    senderReady: session.senderReady,
                    receiverReady: session.receiverReady
                });

                if (session.status === 'started') {
                    broadcastBlackFlashSession(session, {
                        type: 'session_started',
                        inviteId: session.id,
                        sender: session.sender,
                        receiver: session.receiver
                    });
                }
                return;
            }

            if (type === 'end') {
                const { inviteId, player } = msg;
                const session = blackFlashSessions.get(inviteId);
                if (!session) return;
                if (player && player !== session.sender && player !== session.receiver) {
                    sendBlackFlashWs(ws, { type: 'error', message: 'forbidden' });
                    return;
                }
                session.status = 'ended';
                session.updatedAt = nowMs();
                broadcastBlackFlashSession(session, {
                    type: 'session_ended',
                    inviteId: session.id,
                    by: player || null
                });
                blackFlashSessions.delete(inviteId);
                return;
            }

            if (type === 'ping') {
                sendBlackFlashWs(ws, { type: 'pong', time: nowMs() });
            }
        } catch (_) {
            sendBlackFlashWs(ws, { type: 'error', message: 'bad payload' });
        }
    });

    ws.on('close', () => {
        if (currentServerId && currentPlayer) {
            blackFlashSockets.delete(blackFlashPlayerKey(currentServerId, currentPlayer));
        }
    });
});

function chatClientKey(serverId, playerName) {
    return `${serverId}:${playerName}`;
}

const BLOCKED_CHAT_PHRASES = [
    'fuck',
    'fuk',
    'fck',
    'motherfucker',
    'mẹ mày',
    'mẹ mày béo',
    'me may',
    'me may beo',
    'dit me',
    'địt mẹ',
    'đụ mẹ',
    'du me'
];

function sanitizeChatText(text) {
    if (typeof text !== 'string') return '';
    return text.replace(/\s+/g, ' ').trim().slice(0, 240);
}

function escapeRegex(text) {
    return String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function censorBlockedChatText(text) {
    let output = String(text || '');
    for (const phrase of BLOCKED_CHAT_PHRASES) {
        const re = new RegExp(escapeRegex(phrase), 'giu');
        output = output.replace(re, (match) => '#'.repeat(match.length));
    }
    return output;
}

function getServerMemoryHistory(serverId) {
    if (!chatMemoryHistoryByServer.has(serverId)) {
        chatMemoryHistoryByServer.set(serverId, []);
    }
    return chatMemoryHistoryByServer.get(serverId);
}

function pushServerMemoryHistory(serverId, message) {
    const list = getServerMemoryHistory(serverId);
    list.push(message);
    if (list.length > MAX_CHAT_HISTORY) {
        list.splice(0, list.length - MAX_CHAT_HISTORY);
    }
}

async function saveServerChatMessage(message) {
    const payload = {
        server_id: message.serverId,
        place_id: message.placeId || null,
        player_name: message.playerName,
        display_name: message.displayName,
        user_id: message.userId || null,
        text: message.text
    };
    const { error } = await supabase.from('chat_history').insert(payload);
    if (error) {
        throw error;
    }
}

async function pruneServerChatHistory(serverId, limit = MAX_CHAT_HISTORY) {
    const { data, error } = await supabase
        .from('chat_history')
        .select('id')
        .eq('server_id', serverId)
        .order('created_at', { ascending: false })
        .range(limit, limit + 5000);
    if (error || !data || data.length === 0) {
        return;
    }
    const ids = data.map((r) => r.id).filter(Boolean);
    if (ids.length === 0) return;
    await supabase.from('chat_history').delete().in('id', ids);
}

async function fetchServerChatHistory(serverId, limit = MAX_CHAT_HISTORY) {
    const { data, error } = await supabase
        .from('chat_history')
        .select('*')
        .eq('server_id', serverId)
        .order('created_at', { ascending: false })
        .limit(limit);
    if (error) {
        throw error;
    }
    return (data || []).reverse().map((row) => ({
        id: row.id,
        channel: 'server',
        serverId: row.server_id,
        placeId: row.place_id,
        playerName: row.player_name,
        displayName: row.display_name || row.player_name,
        userId: row.user_id || 0,
        text: row.text,
        createdAt: row.created_at || new Date().toISOString()
    }));
}

function sendChatWs(ws, payload) {
    try {
        if (!ws || ws.readyState !== WebSocket.OPEN) return;
        ws.send(JSON.stringify(payload));
    } catch (_) {}
}

function broadcastServerChat(serverId, payload) {
    for (const client of chatClients) {
        if (!client || !client.meta || client.meta.serverId !== serverId) continue;
        sendChatWs(client, payload);
    }
}

function broadcastGlobalChannel(payload) {
    for (const client of chatClients) {
        if (!client || !client.meta) continue;
        sendChatWs(client, payload);
    }
}

function chatSocketOf(serverId, playerName) {
    for (const client of chatClients) {
        if (!client || !client.meta) continue;
        if (client.meta.serverId === serverId && client.meta.playerName === playerName) {
            return client;
        }
    }
    return null;
}

function makePrivateRoomId(serverId, p1, p2) {
    const sorted = [String(p1 || '').trim(), String(p2 || '').trim()].sort();
    return `pm_${serverId}_${sorted[0]}_${sorted[1]}`;
}

function getOrCreatePrivateRoom(serverId, p1, p2) {
    const id = makePrivateRoomId(serverId, p1, p2);
    let room = privateChatRooms.get(id);
    if (!room) {
        room = {
            id,
            serverId,
            players: [p1, p2],
            createdAt: Date.now(),
            updatedAt: Date.now()
        };
        privateChatRooms.set(id, room);
    } else {
        room.updatedAt = Date.now();
    }
    return room;
}

function cleanupPrivateRooms() {
    const now = Date.now();
    for (const [id, room] of privateChatRooms.entries()) {
        if (!room || now - (room.updatedAt || now) > PRIVATE_ROOM_TTL_MS) {
            privateChatRooms.delete(id);
        }
    }
}

function isPlayerInRoom(room, playerName) {
    return !!room && Array.isArray(room.players) && room.players.includes(playerName);
}

function broadcastPrivateRoom(room, payload) {
    if (!room || !Array.isArray(room.players)) return;
    for (const playerName of room.players) {
        const sock = chatSocketOf(room.serverId, playerName);
        if (sock) {
            sendChatWs(sock, payload);
        }
    }
}

robloxChatWsServer.on('connection', (ws) => {
    ws.meta = null;
    sendChatWs(ws, { type: 'connected' });

    ws.on('message', async (raw) => {
        try {
            cleanupPrivateRooms();
            const msg = JSON.parse(raw.toString());
            const type = msg && msg.type;

            if (type === 'register') {
                const serverId = String(msg.serverId || '').trim();
                const placeId = Number(msg.placeId || 0) || 0;
                const playerName = String(msg.playerName || '').trim();
                const displayNameRaw = String(msg.displayName || '').trim();
                const displayName = displayNameRaw || playerName;
                const userId = Number(msg.userId || 0) || 0;
                if (!serverId || !playerName) {
                    sendChatWs(ws, { type: 'error', message: 'missing register data' });
                    return;
                }
                ws.meta = {
                    key: chatClientKey(serverId, playerName),
                    serverId,
                    placeId,
                    playerName,
                    displayName,
                    userId
                };
                chatClients.add(ws);
                let history = [];
                try {
                    history = await fetchServerChatHistory(serverId, MAX_CHAT_HISTORY);
                } catch (_) {
                    history = getServerMemoryHistory(serverId);
                }
                sendChatWs(ws, {
                    type: 'registered',
                    serverId,
                    playerName,
                    history
                });
                return;
            }

            if (!ws.meta) {
                sendChatWs(ws, { type: 'error', message: 'not registered' });
                return;
            }

            if (type === 'chat_message') {
                const channel = String(msg.channel || 'server').toLowerCase();
                let text = sanitizeChatText(msg.text);
                if (!text) {
                    return;
                }
                text = censorBlockedChatText(text);
                if (!['server', 'en', 'vn'].includes(channel)) {
                    sendChatWs(ws, { type: 'error', message: 'invalid channel' });
                    return;
                }

                const out = {
                    id: `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
                    type: 'chat_message',
                    channel,
                    serverId: ws.meta.serverId,
                    placeId: ws.meta.placeId,
                    playerName: ws.meta.playerName,
                    displayName: ws.meta.displayName,
                    userId: ws.meta.userId,
                    text,
                    createdAt: new Date().toISOString()
                };

                if (channel === 'server') {
                    pushServerMemoryHistory(ws.meta.serverId, out);
                    try {
                        await saveServerChatMessage(out);
                        await pruneServerChatHistory(ws.meta.serverId, MAX_CHAT_HISTORY);
                    } catch (_) {}
                    broadcastServerChat(ws.meta.serverId, out);
                } else {
                    broadcastGlobalChannel(out);
                }
                return;
            }

            if (type === 'private_open') {
                const targetName = String(msg.targetName || '').trim();
                if (!targetName || targetName === ws.meta.playerName) {
                    sendChatWs(ws, { type: 'error', message: 'invalid target' });
                    return;
                }
                const targetSocket = chatSocketOf(ws.meta.serverId, targetName);
                if (!targetSocket) {
                    sendChatWs(ws, { type: 'error', message: 'target offline' });
                    return;
                }

                const room = getOrCreatePrivateRoom(ws.meta.serverId, ws.meta.playerName, targetName);
                const forSender = {
                    type: 'private_opened',
                    roomId: room.id,
                    targetName,
                    roomName: `PM ${targetName}`
                };
                const forTarget = {
                    type: 'private_opened',
                    roomId: room.id,
                    targetName: ws.meta.playerName,
                    roomName: `PM ${ws.meta.playerName}`
                };
                sendChatWs(ws, forSender);
                sendChatWs(targetSocket, forTarget);
                return;
            }

            if (type === 'private_message') {
                const roomId = String(msg.roomId || '').trim();
                const room = privateChatRooms.get(roomId);
                if (!room || room.serverId !== ws.meta.serverId || !isPlayerInRoom(room, ws.meta.playerName)) {
                    sendChatWs(ws, { type: 'error', message: 'private room not found' });
                    return;
                }
                let text = sanitizeChatText(msg.text);
                if (!text) return;
                text = censorBlockedChatText(text);
                room.updatedAt = Date.now();
                const out = {
                    id: `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
                    type: 'chat_message',
                    channel: 'private',
                    roomId,
                    serverId: ws.meta.serverId,
                    placeId: ws.meta.placeId,
                    playerName: ws.meta.playerName,
                    displayName: ws.meta.displayName,
                    userId: ws.meta.userId,
                    text,
                    createdAt: new Date().toISOString()
                };
                broadcastPrivateRoom(room, out);
                return;
            }

            if (type === 'private_close') {
                const roomId = String(msg.roomId || '').trim();
                const room = privateChatRooms.get(roomId);
                if (!room || room.serverId !== ws.meta.serverId || !isPlayerInRoom(room, ws.meta.playerName)) {
                    return;
                }
                privateChatRooms.delete(roomId);
                broadcastPrivateRoom(room, {
                    type: 'private_closed',
                    roomId,
                    by: ws.meta.playerName
                });
                return;
            }

            if (type === 'ping') {
                sendChatWs(ws, { type: 'pong', time: Date.now() });
            }
        } catch (_) {
            sendChatWs(ws, { type: 'error', message: 'bad payload' });
        }
    });

    ws.on('close', () => {
        if (ws.meta && ws.meta.serverId && ws.meta.playerName) {
            for (const [roomId, room] of privateChatRooms.entries()) {
                if (room.serverId !== ws.meta.serverId) continue;
                if (!isPlayerInRoom(room, ws.meta.playerName)) continue;
                privateChatRooms.delete(roomId);
                broadcastPrivateRoom(room, {
                    type: 'private_closed',
                    roomId,
                    by: ws.meta.playerName
                });
            }
        }
        chatClients.delete(ws);
    });
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
      
        const newKey = generateRandomKey(18);
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
app.post('/api/blackflash/invite', (req, res) => {
    try {
        cleanupBlackFlashSessions();
        const { sender, receiver, serverId, placeId } = req.body || {};
        if (!sender || !receiver || !serverId) {
            return res.status(400).json({ success: false, message: 'Thiếu sender/receiver/serverId' });
        }
        if (sender === receiver) {
            return res.status(400).json({ success: false, message: 'Không thể tự mời chính mình' });
        }

        for (const session of blackFlashSessions.values()) {
            const samePair = session.serverId === serverId &&
                ((session.sender === sender && session.receiver === receiver) ||
                 (session.sender === receiver && session.receiver === sender));
            const active = ['pending', 'accepted', 'started'].includes(session.status);
            if (samePair && active) {
                session.updatedAt = nowMs();
                return res.json({
                    success: true,
                    data: {
                        inviteId: session.id,
                        status: session.status
                    }
                });
            }
        }

        const id = createBlackFlashId();
        blackFlashSessions.set(id, {
            id,
            sender,
            receiver,
            serverId,
            placeId: placeId || null,
            status: 'pending',
            senderReady: false,
            receiverReady: false,
            createdAt: nowMs(),
            updatedAt: nowMs()
        });

        return res.json({
            success: true,
            data: {
                inviteId: id,
                status: 'pending'
            }
        });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'Lỗi server nội bộ' });
    }
});
app.post('/api/blackflash/respond', (req, res) => {
    try {
        cleanupBlackFlashSessions();
        const { inviteId, player, accepted, serverId } = req.body || {};
        if (!inviteId || !player) {
            return res.status(400).json({ success: false, message: 'Thiếu inviteId/player' });
        }
        const session = blackFlashSessions.get(inviteId);
        if (!session) {
            return res.status(404).json({ success: false, message: 'Không tìm thấy lời mời' });
        }
        if (serverId && session.serverId !== serverId) {
            return res.status(400).json({ success: false, message: 'Sai server' });
        }
        if (session.receiver !== player && session.sender !== player) {
            return res.status(403).json({ success: false, message: 'Không có quyền phản hồi lời mời này' });
        }

        if (!accepted) {
            session.status = 'rejected';
            session.updatedAt = nowMs();
            return res.json({ success: true, data: { inviteId, status: session.status } });
        }

        session.status = 'accepted';
        session.updatedAt = nowMs();
        return res.json({
            success: true,
            data: {
                inviteId,
                status: session.status,
                sender: session.sender,
                receiver: session.receiver
            }
        });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'Lỗi server nội bộ' });
    }
});
app.post('/api/blackflash/start', (req, res) => {
    try {
        cleanupBlackFlashSessions();
        const { inviteId, player, role, ready, serverId } = req.body || {};
        if (!inviteId || !player) {
            return res.status(400).json({ success: false, message: 'Thiếu inviteId/player' });
        }
        const session = blackFlashSessions.get(inviteId);
        if (!session) {
            return res.status(404).json({ success: false, message: 'Không tìm thấy phòng blackflash' });
        }
        if (serverId && session.serverId !== serverId) {
            return res.status(400).json({ success: false, message: 'Sai server' });
        }

        const setReady = ready !== false;
        if (player === session.sender || role === 'sender') {
            session.senderReady = setReady;
        } else if (player === session.receiver || role === 'receiver') {
            session.receiverReady = setReady;
        } else {
            return res.status(403).json({ success: false, message: 'Không có quyền start phòng này' });
        }

        if (session.senderReady && session.receiverReady) {
            session.status = 'started';
        } else if (session.status !== 'rejected' && session.status !== 'ended') {
            session.status = 'accepted';
        }
        session.updatedAt = nowMs();

        return res.json({
            success: true,
            data: {
                inviteId,
                status: session.status,
                senderReady: session.senderReady,
                receiverReady: session.receiverReady
            }
        });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'Lỗi server nội bộ' });
    }
});
app.post('/api/blackflash/poll', (req, res) => {
    try {
        cleanupBlackFlashSessions();
        const { player, serverId } = req.body || {};
        if (!player || !serverId) {
            return res.status(400).json({ success: false, message: 'Thiếu player/serverId' });
        }

        let incomingInvite = null;
        let sessionData = null;

        for (const session of blackFlashSessions.values()) {
            if (session.serverId !== serverId) continue;
            if (!incomingInvite && session.status === 'pending' && session.receiver === player) {
                incomingInvite = {
                    inviteId: session.id,
                    sender: session.sender,
                    receiver: session.receiver
                };
            }

            const active = ['accepted', 'started'].includes(session.status);
            if (!sessionData && active && (session.sender === player || session.receiver === player)) {
                const isSender = session.sender === player;
                sessionData = {
                    inviteId: session.id,
                    status: session.status,
                    accepted: session.status === 'accepted' || session.status === 'started',
                    partnerName: isSender ? session.receiver : session.sender,
                    partnerReady: isSender ? session.receiverReady : session.senderReady
                };
            }
        }

        return res.json({
            success: true,
            data: {
                incomingInvite,
                session: sessionData
            }
        });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'Lỗi server nội bộ' });
    }
});
app.post('/api/blackflash/end', (req, res) => {
    try {
        const { inviteId, player } = req.body || {};
        if (!inviteId) {
            return res.status(400).json({ success: false, message: 'Thiếu inviteId' });
        }
        const session = blackFlashSessions.get(inviteId);
        if (!session) {
            return res.json({ success: true, data: { inviteId, status: 'ended' } });
        }
        if (player && player !== session.sender && player !== session.receiver) {
            return res.status(403).json({ success: false, message: 'Không có quyền kết thúc session' });
        }
        session.status = 'ended';
        session.updatedAt = nowMs();
        blackFlashSessions.delete(inviteId);
        return res.json({ success: true, data: { inviteId, status: 'ended' } });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'Lỗi server nội bộ' });
    }
});
app.post('/api/chat/server/send', async (req, res) => {
    try {
        const serverId = String(req.body?.serverId || '').trim();
        const placeId = Number(req.body?.placeId || 0) || 0;
        const playerName = String(req.body?.playerName || '').trim();
        const displayNameRaw = String(req.body?.displayName || '').trim();
        const displayName = displayNameRaw || playerName;
        const userId = Number(req.body?.userId || 0) || 0;
        let text = sanitizeChatText(req.body?.text);

        if (!serverId || !playerName || !text) {
            return res.status(400).json({ success: false, message: 'missing serverId/playerName/text' });
        }
        text = censorBlockedChatText(text);

        const out = {
            id: `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
            type: 'chat_message',
            channel: 'server',
            serverId,
            placeId,
            playerName,
            displayName,
            userId,
            text,
            createdAt: new Date().toISOString()
        };

        pushServerMemoryHistory(serverId, out);
        try {
            await saveServerChatMessage(out);
            await pruneServerChatHistory(serverId, MAX_CHAT_HISTORY);
        } catch (_) {}
        broadcastServerChat(serverId, out);
        return res.json({ success: true, data: out });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'internal server error' });
    }
});
app.get('/api/chat/server/history', async (req, res) => {
    try {
        const serverId = String(req.query?.serverId || '').trim();
        const limit = Math.min(Math.max(Number(req.query?.limit || MAX_CHAT_HISTORY) || MAX_CHAT_HISTORY, 1), MAX_CHAT_HISTORY);
        if (!serverId) {
            return res.status(400).json({ success: false, message: 'missing serverId' });
        }

        let history = [];
        try {
            history = await fetchServerChatHistory(serverId, limit);
        } catch (_) {
            const memoryHistory = getServerMemoryHistory(serverId);
            history = memoryHistory.slice(Math.max(0, memoryHistory.length - limit));
        }

        return res.json({
            success: true,
            data: {
                serverId,
                history
            }
        });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'internal server error' });
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
            adminLogin: 'POST /admin/login',
            chatHistory: 'GET /api/chat/server/history?serverId=...',
            chatSend: 'POST /api/chat/server/send',
            chatWs: '/chat-ws'
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
