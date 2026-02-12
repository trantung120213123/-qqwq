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
const MAX_CHAT_HISTORY = 50;
const PUBLIC_CHAT_CHANNELS = ['server', 'en', 'vn', 'global'];
const SHARED_PUBLIC_HISTORY_SERVER_ID = '__shared_public__';
const OWNER_USERNAME = 'tahabase2022';
const HISTORY_LOAD_LIMIT_BY_CHANNEL = {
    server: 20,
    en: 50,
    vn: 50,
    global: 50
};
const privateChatRooms = new Map();
const PRIVATE_ROOM_TTL_MS = 2 * 60 * 60 * 1000;
const pendingPrivateInvites = new Map();
const pendingPrivateRoomOpens = new Map();
const PRIVATE_INVITE_TTL_MS = 2 * 60 * 1000;
const WARNING_LIMIT = 3;
const RATE_LIMIT_MIN_INTERVAL_MS = 1000;
const RATE_LIMIT_BURST_WINDOW_MS = 3000;
const RATE_LIMIT_BURST_COUNT = 5;
const RATE_LIMIT_BURST_MUTE_MS = 30 * 1000;
const PRIVATE_CHAT_COOLDOWN_MS = 1500;
const MAX_CHAT_TEXT_LENGTH = 150;
const STRIKE_DECAY_MS = 14 * 24 * 60 * 60 * 1000;
const chatRateStateByUser = new Map();
const MASKED_MESSAGE_TEXT = '############';
const adminMuteCache = new Map();
const userMutePairCache = new Map();
const modRoleCache = new Map();
const MOD_ROLE_CACHE_TTL_MS = 60 * 1000;
const MUTE_STEPS_MS = [
    24 * 60 * 60 * 1000, // 1 day
    3 * 24 * 60 * 60 * 1000, // 3 days
    7 * 24 * 60 * 60 * 1000, // 1 week
    30 * 24 * 60 * 60 * 1000 // 1 month
];
const MAX_CHAT_LEVEL = 10;
const LEVEL_XP_PUBLIC_MESSAGE = 4;
const LEVEL_XP_PRIVATE_MESSAGE = 3;
const LEVEL_XP_VIOLATION_PENALTY = 18;
const LEVEL_XP_WARNING_PENALTY = 8;
const XP_REWARD_WINDOW_MS = 10 * 1000;
const XP_REPEAT_SAME_TEXT_MS = 900;
const xpRewardStateByUser = new Map();

function nowMs() {
    return Date.now();
}

function historyLoadLimitForChannel(channel, fallback = MAX_CHAT_HISTORY) {
    const key = normalizePublicChannel(channel, '');
    const fromMap = Number(HISTORY_LOAD_LIMIT_BY_CHANNEL[key] || 0) || 0;
    if (fromMap > 0) return fromMap;
    return Number(fallback || MAX_CHAT_HISTORY) || MAX_CHAT_HISTORY;
}

function normalizePublicChannel(channel, fallback = 'server') {
    const key = String(channel || '').trim().toLowerCase();
    const mapped = key === 'gobal' ? 'global' : key;
    if (PUBLIC_CHAT_CHANNELS.includes(mapped)) return mapped;
    return fallback;
}

function scopedHistoryServerId(serverId, channel = 'server') {
    const normalizedChannel = normalizePublicChannel(channel, 'server');
    if (normalizedChannel === 'server') {
        return String(serverId || '').trim();
    }
    return SHARED_PUBLIC_HISTORY_SERVER_ID;
}

function isOwnerName(name) {
    return String(name || '').trim().toLowerCase() === OWNER_USERNAME;
}

function cleanupChatClients() {
    for (const client of chatClients) {
        if (!client || client.readyState !== WebSocket.OPEN) {
            chatClients.delete(client);
        }
    }
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

const BLOCKED_CHAT_PATTERNS = [
    // Severe profanity / harassment
    { label: 'abuse', regex: /\bđ[ịi]t\b/giu },
    { label: 'abuse', regex: /\bdit\b/giu },
    { label: 'abuse', regex: /\bc[ạa]c\b/giu },
    { label: 'abuse', regex: /\bfuck\b/giu },
    // User-targeted harassment phrase requested
    { label: 'abuse', regex: /\bdavid[\s._-]*backzuki\b/giu },
    // Gore / excessive violence
    { label: 'gore', regex: /\bch[ặa]t[\s._-]*đ[ầa]u\b/giu },
    { label: 'gore', regex: /\bchat[\s._-]*dau\b/giu },
    { label: 'gore', regex: /\bđ[ứu]t[\s._-]*đ[ầa]u\b/giu },
    { label: 'gore', regex: /\bdut[\s._-]*dau\b/giu },
    { label: 'gore', regex: /\bc[ắa]t[\s._-]*c[ổo]\b/giu },
    { label: 'gore', regex: /\bcat[\s._-]*co\b/giu },
    { label: 'gore', regex: /\bm[óo]c[\s._-]*m[ắa]t\b/giu },
    { label: 'gore', regex: /\bmoc[\s._-]*mat\b/giu },
    { label: 'gore', regex: /\bm[óo]i[\s._-]*ru[ộo]t\b/giu },
    { label: 'gore', regex: /\bmoi[\s._-]*ruot\b/giu },
    { label: 'gore', regex: /\bx[ẻe][\s._-]*x[áa]c\b/giu },
    { label: 'gore', regex: /\bxe[\s._-]*xac\b/giu },
    { label: 'gore', regex: /\bphanh[\s._-]*th[âa]y\b/giu },
    { label: 'gore', regex: /\bbehead\b/giu },
    { label: 'gore', regex: /\bdecapitate\b/giu },
    { label: 'gore', regex: /\bdismember\b/giu }
];

const BLOCKED_CANONICAL_TERMS = [
    'fuck',
    'dit',
    'ditme',
    'cac',
    'davidbackzuki',
    'chatdau',
    'dutdau',
    'catco',
    'mocmat',
    'moiruot',
    'xexac',
    'phanhthay',
    'behead',
    'decapitate',
    'dismember'
];

function sanitizeChatText(text) {
    if (typeof text !== 'string') return '';
    return text.replace(/\s+/g, ' ').trim().slice(0, MAX_CHAT_TEXT_LENGTH);
}

function normalizeChatRewardText(text) {
    return sanitizeChatText(text)
        .toLowerCase()
        .replace(/\s+/g, ' ');
}

function sanitizeReplyMeta(replyTo) {
    if (!replyTo || typeof replyTo !== 'object') return null;
    const id = String(replyTo.id || '').trim().slice(0, 64);
    const playerName = String(replyTo.playerName || '').trim().slice(0, 32);
    const preview = sanitizeChatText(String(replyTo.preview || '')).slice(0, 60);
    if (!id && !playerName && !preview) return null;
    return {
        id: id || null,
        playerName: playerName || 'Unknown',
        preview: preview || ''
    };
}

function cloneRegexWithGlobal(re) {
    const flags = re.flags.includes('g') ? re.flags : `${re.flags}g`;
    return new RegExp(re.source, flags);
}

function normalizePolicyText(text) {
    return String(text || '')
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .toLowerCase();
}

function normalizeForPhraseDetection(text) {
    return normalizePolicyText(text)
        .replace(/[!|1]/g, 'i')
        .replace(/3/g, 'e')
        .replace(/4|@/g, 'a')
        .replace(/5|\$/g, 's')
        .replace(/0/g, 'o')
        .replace(/7|\+/g, 't')
        .replace(/[^a-z0-9]/g, '');
}

function censorBlockedChatText(text) {
    let output = String(text || '');
    for (const rule of BLOCKED_CHAT_PATTERNS) {
        const regex = cloneRegexWithGlobal(rule.regex);
        output = output.replace(regex, '##');
    }
    return output;
}

function hasBlockedLink(text) {
    const normalized = normalizePolicyText(text);
    const noSpaces = normalized.replace(/\s+/g, '');
    if (/https?:\/\//.test(noSpaces) || /www\./.test(noSpaces) || /discord\.gg/.test(noSpaces)) {
        return true;
    }
    const flattened = normalizeForPhraseDetection(normalized);
    if (flattened.includes('discordgg') || flattened.includes('http') || flattened.includes('https') || flattened.includes('www')) {
        return true;
    }
    return /[a-z0-9]{2,}(com|io|sx|h)\b/.test(flattened);
}

function censorBlockedLinks(text) {
    const regex = /(https?:\/\/\S+|www\.\S+|[a-z0-9][a-z0-9\-\/\\\.]{1,90}\.(?:com|io|sx|h)\S*)/giu;
    return String(text || '').replace(regex, '##');
}

function applyContentPolicy(text) {
    let output = String(text || '');
    const reasons = new Set();
    let matched = false;

    for (const rule of BLOCKED_CHAT_PATTERNS) {
        const regex = cloneRegexWithGlobal(rule.regex);
        if (regex.test(output)) {
            matched = true;
            reasons.add(rule.label);
            output = output.replace(regex, '##');
        }
    }

    const normalizedCompact = normalizeForPhraseDetection(output);
    for (const term of BLOCKED_CANONICAL_TERMS) {
        if (normalizedCompact.includes(term)) {
            matched = true;
            reasons.add('abuse');
            output = '##';
            break;
        }
    }

    output = output.trim();
    if (!output) {
        output = '##';
    }

    return {
        text: output,
        violated: matched,
        reasons: Array.from(reasons)
    };
}

function policyUserKey(userId, playerName) {
    const numeric = Number(userId || 0) || 0;
    if (numeric > 0) return `uid:${numeric}`;
    const name = String(playerName || '').trim().toLowerCase();
    return `name:${name}`;
}

function policyUserKeys(userId, playerName) {
    const keys = [];
    const numeric = Number(userId || 0) || 0;
    const name = String(playerName || '').trim().toLowerCase();
    if (numeric > 0) keys.push(`uid:${numeric}`);
    if (name) keys.push(`name:${name}`);
    return Array.from(new Set(keys));
}

function buildSenderMeta({ serverId, placeId, playerName, displayName, userId }) {
    return {
        serverId: String(serverId || '').trim(),
        placeId: Number(placeId || 0) || 0,
        playerName: String(playerName || '').trim(),
        displayName: String(displayName || '').trim() || String(playerName || '').trim(),
        userId: Number(userId || 0) || 0
    };
}

function levelXpRequired(level) {
    const safeLevel = Math.max(1, Math.min(MAX_CHAT_LEVEL, Number(level || 1)));
    return 28 + ((safeLevel - 1) * 14);
}

function normalizeLevelState(meta, row) {
    return {
        user_key: policyUserKey(meta.userId, meta.playerName),
        user_id: meta.userId || null,
        player_name: meta.playerName,
        level: Math.max(1, Math.min(MAX_CHAT_LEVEL, Number(row?.level || 1))),
        xp: Math.max(0, Number(row?.xp || 0))
    };
}

function levelStyleName(level) {
    const lv = Math.max(1, Math.min(MAX_CHAT_LEVEL, Number(level || 1)));
    if (lv >= 10) return 'nova';
    if (lv >= 9) return 'mythic';
    if (lv >= 8) return 'radiant';
    if (lv >= 7) return 'diamond';
    if (lv >= 6) return 'platinum';
    if (lv >= 5) return 'gold';
    if (lv >= 4) return 'emerald';
    if (lv >= 3) return 'sapphire';
    if (lv >= 2) return 'glow';
    return 'base';
}

function applyLevelXpDelta(state, xpDelta) {
    const next = {
        ...state,
        level: Math.max(1, Math.min(MAX_CHAT_LEVEL, Number(state.level || 1))),
        xp: Math.max(0, Number(state.xp || 0))
    };
    let delta = Number(xpDelta || 0);
    if (!Number.isFinite(delta) || delta === 0) return next;

    if (delta > 0) {
        if (next.level >= MAX_CHAT_LEVEL) {
            next.xp = 0;
            return next;
        }
        next.xp += delta;
        while (next.level < MAX_CHAT_LEVEL) {
            const req = levelXpRequired(next.level);
            if (next.xp < req) break;
            next.xp -= req;
            next.level += 1;
        }
        if (next.level >= MAX_CHAT_LEVEL) {
            next.level = MAX_CHAT_LEVEL;
            next.xp = 0;
        }
        return next;
    }

    next.xp += delta;
    while (next.xp < 0 && next.level > 1) {
        next.level -= 1;
        next.xp += levelXpRequired(next.level);
    }
    if (next.level <= 1 && next.xp < 0) {
        next.level = 1;
        next.xp = 0;
    }
    return next;
}

async function getPlayerLevelState(meta) {
    const userKey = policyUserKey(meta.userId, meta.playerName);
    try {
        const { data, error } = await supabase
            .from('chat_player_levels')
            .select('user_key,user_id,player_name,level,xp')
            .eq('user_key', userKey)
            .maybeSingle();
        if (error) throw error;
        if (!data) {
            const initial = normalizeLevelState(meta, { level: 1, xp: 0 });
            await supabase
                .from('chat_player_levels')
                .upsert(initial, { onConflict: 'user_key' });
            return initial;
        }
        return normalizeLevelState(meta, data);
    } catch (_) {
        return normalizeLevelState(meta, { level: 1, xp: 0 });
    }
}

async function savePlayerLevelState(state) {
    try {
        await supabase
            .from('chat_player_levels')
            .upsert({
                user_key: state.user_key,
                user_id: state.user_id || null,
                player_name: state.player_name || null,
                level: Math.max(1, Math.min(MAX_CHAT_LEVEL, Number(state.level || 1))),
                xp: Math.max(0, Number(state.xp || 0))
            }, { onConflict: 'user_key' });
    } catch (_) {}
}

async function applyPlayerXp(meta, xpDelta) {
    if (!meta || !meta.playerName) {
        return { level: 1, xp: 0, style: levelStyleName(1) };
    }
    if (await isAdminAccount(meta.playerName)) {
        const adminLevel = MAX_CHAT_LEVEL;
        return { level: adminLevel, xp: 0, style: levelStyleName(adminLevel) };
    }

    const current = await getPlayerLevelState(meta);
    const next = applyLevelXpDelta(current, xpDelta);
    next.user_id = meta.userId || next.user_id || null;
    next.player_name = meta.playerName || next.player_name || null;
    await savePlayerLevelState(next);
    return {
        level: next.level,
        xp: next.xp,
        style: levelStyleName(next.level)
    };
}

function calculateMessageXpGain(meta, text, options = {}) {
    const isPrivate = !!options.isPrivate;
    const base = isPrivate ? LEVEL_XP_PRIVATE_MESSAGE : LEVEL_XP_PUBLIC_MESSAGE;
    const key = policyUserKey(meta.userId, meta.playerName);
    const now = Date.now();
    const normalized = normalizeChatRewardText(text);

    const prev = xpRewardStateByUser.get(key) || {
        windowStart: now,
        burstCount: 0,
        lastAt: 0,
        lastText: ''
    };
    if ((now - prev.windowStart) > XP_REWARD_WINDOW_MS) {
        prev.windowStart = now;
        prev.burstCount = 0;
    }
    prev.burstCount += 1;

    let reward = base;
    if (normalized.length < 6) {
        reward = Math.max(1, reward - 2);
    }
    if ((now - prev.lastAt) <= XP_REPEAT_SAME_TEXT_MS && normalized && normalized === prev.lastText) {
        reward = 0;
    } else if (prev.burstCount >= 8) {
        reward = 0;
    } else if (prev.burstCount >= 5) {
        reward = Math.max(1, Math.floor(reward / 2));
    }

    prev.lastAt = now;
    prev.lastText = normalized;
    xpRewardStateByUser.set(key, prev);
    return reward;
}

function calculateViolationPenalty(basePenalty, level, reasons, strikeLevel) {
    let penalty = Math.max(1, Math.abs(Number(basePenalty || LEVEL_XP_VIOLATION_PENALTY)));
    const lv = Math.max(1, Number(level || 1) || 1);
    const sl = Math.max(0, Number(strikeLevel || 0) || 0);
    if (lv >= 8) {
        penalty += (lv - 7) * 8;
    } else if (lv >= 5) {
        penalty += (lv - 4) * 4;
    }
    if (sl > 0) {
        penalty += Math.min(20, sl * 2);
    }
    const reasonSet = new Set(Array.isArray(reasons) ? reasons : []);
    if (reasonSet.has('gore')) penalty += 8;
    if (reasonSet.has('link')) penalty += 5;
    if (reasonSet.has('abuse')) penalty += 4;
    return Math.max(1, penalty);
}

async function getPlayerVisual(meta) {
    if (!meta || !meta.playerName) {
        return { level: 1, xp: 0, style: levelStyleName(1) };
    }
    if (await isAdminAccount(meta.playerName)) {
        return { level: MAX_CHAT_LEVEL, xp: 0, style: levelStyleName(MAX_CHAT_LEVEL) };
    }
    const state = await getPlayerLevelState(meta);
    return {
        level: state.level,
        xp: state.xp,
        style: levelStyleName(state.level)
    };
}

function usernameLower(name) {
    return String(name || '').trim().toLowerCase();
}

function normalizeUsernameInput(value) {
    let name = String(value || '').trim();
    if (name.startsWith('@')) name = name.slice(1);
    return name.trim();
}

function parseDurationHms(input) {
    const raw = String(input || '').trim();
    const m = raw.match(/^(\d{1,3}):([0-5]\d):([0-5]\d)$/);
    if (!m) return null;
    const hours = Number(m[1]);
    const mins = Number(m[2]);
    const secs = Number(m[3]);
    const total = (hours * 3600) + (mins * 60) + secs;
    if (!Number.isFinite(total) || total <= 0) return null;
    return total * 1000;
}

function parseDurationShort(input) {
    const raw = String(input || '').trim().toLowerCase();
    const m = raw.match(/^(\d+)([smhd])$/);
    if (!m) return null;
    const value = Number(m[1]);
    if (!Number.isFinite(value) || value <= 0) return null;
    const unit = m[2];
    let scale = 24 * 60 * 60 * 1000;
    if (unit === 's') scale = 1000;
    else if (unit === 'm') scale = 60 * 1000;
    else if (unit === 'h') scale = 60 * 60 * 1000;
    return value * scale;
}

async function getChatRole(username) {
    const uname = usernameLower(username);
    if (!uname) return 'user';
    if (isOwnerName(uname)) return 'admin';

    const now = Date.now();
    const cached = modRoleCache.get(uname);
    if (cached && cached.expiresAt > now) {
        return cached.role;
    }

    const { data, error } = await supabase
        .from('staff_roles')
        .select('role')
        .eq('username_lower', uname)
        .limit(1)
        .maybeSingle();
    if (error) return 'user';
    const role = (data?.role === 'admin' || data?.role === 'mod') ? data.role : 'user';
    modRoleCache.set(uname, { role, expiresAt: now + MOD_ROLE_CACHE_TTL_MS });
    return role;
}

async function isAdminAccount(username) {
    return (await getChatRole(username)) === 'admin';
}

function invalidateModRoleCache(username) {
    modRoleCache.delete(usernameLower(username));
}

function staffCanModerateTarget(senderRole, targetRole) {
    if (senderRole === 'admin') {
        return targetRole !== 'admin';
    }
    if (senderRole === 'mod') {
        return targetRole === 'user';
    }
    return false;
}

async function logStaffAction({ actorMeta, actorRole, action, targetMeta = null, detail = null }) {
    try {
        await supabase
            .from('staff_action_logs')
            .insert({
                actor_user_key: policyUserKey(actorMeta?.userId, actorMeta?.playerName),
                actor_username: actorMeta?.playerName || null,
                actor_username_lower: usernameLower(actorMeta?.playerName),
                actor_role: actorRole || 'user',
                action: action,
                target_user_key: targetMeta ? policyUserKey(targetMeta.userId, targetMeta.playerName) : null,
                target_username: targetMeta?.playerName || null,
                target_username_lower: usernameLower(targetMeta?.playerName),
                detail: detail || null
            });
    } catch (_) {}
}

function userMutePairKey(serverId, muterName, targetName) {
    return `${String(serverId || '').trim()}::${usernameLower(muterName)}->${usernameLower(targetName)}`;
}

function cleanupMuteCaches() {
    const now = Date.now();
    for (const [key, until] of adminMuteCache.entries()) {
        if (!until || until <= now) adminMuteCache.delete(key);
    }
    for (const [key, until] of userMutePairCache.entries()) {
        if (!until || until <= now) userMutePairCache.delete(key);
    }
}

async function logChatMessageAudit(payload) {
    try {
        await supabase.from('message_logs').insert({
            server_id: payload.serverId || null,
            channel: payload.channel || null,
            room_id: payload.roomId || null,
            player_name: payload.playerName || 'unknown',
            display_name: payload.displayName || null,
            user_id: payload.userId || null,
            text_sanitized: payload.textSanitized || '',
            text_original: payload.textOriginal || null,
            moderation_reasons: payload.reasons || null,
            is_masked: !!payload.isMasked
        });
    } catch (_) {}
}

async function getBanState(meta) {
    if (await isAdminAccount(meta.playerName)) {
        return null;
    }
    const key = policyUserKey(meta.userId, meta.playerName);
    const uname = usernameLower(meta.playerName);
    const nowIso = new Date().toISOString();

    let { data, error } = await supabase
        .from('ban_list')
        .select('*')
        .eq('user_key', key)
        .limit(1)
        .maybeSingle();
    if (error) throw error;
    if (!data) {
        ({ data, error } = await supabase
            .from('ban_list')
            .select('*')
            .eq('username_lower', uname)
            .limit(1)
            .maybeSingle());
        if (error) throw error;
    }
    if (!data) return null;

    if (data.is_permanent) return data;
    if (!data.banned_until) return null;
    if (new Date(data.banned_until).toISOString() <= nowIso) return null;
    return data;
}

async function getAdminMuteState(meta) {
    if (await isAdminAccount(meta.playerName)) {
        return null;
    }
    cleanupMuteCaches();
    const key = policyUserKey(meta.userId, meta.playerName);
    if (adminMuteCache.has(key)) {
        const untilMs = adminMuteCache.get(key);
        return new Date(untilMs);
    }

    const uname = usernameLower(meta.playerName);
    const nowIso = new Date().toISOString();
    let { data, error } = await supabase
        .from('mute_list')
        .select('*')
        .eq('user_key', key)
        .gt('muted_until', nowIso)
        .limit(1)
        .maybeSingle();
    if (error) throw error;
    if (!data) {
        ({ data, error } = await supabase
            .from('mute_list')
            .select('*')
            .eq('username_lower', uname)
            .gt('muted_until', nowIso)
            .limit(1)
            .maybeSingle());
        if (error) throw error;
    }
    if (!data) return null;
    const untilMs = new Date(data.muted_until).getTime();
    if (Number.isFinite(untilMs)) adminMuteCache.set(key, untilMs);
    return new Date(untilMs);
}

async function upsertAdminMute(targetMeta, mutedBy, durationMs, reason = null) {
    const until = new Date(Date.now() + durationMs).toISOString();
    const payload = {
        user_key: policyUserKey(targetMeta.userId, targetMeta.playerName),
        username: targetMeta.playerName,
        username_lower: usernameLower(targetMeta.playerName),
        user_id: targetMeta.userId || null,
        muted_by: mutedBy,
        reason: reason || null,
        muted_until: until
    };
    const { error } = await supabase
        .from('mute_list')
        .upsert(payload, { onConflict: 'user_key' });
    if (error) throw error;
    adminMuteCache.set(payload.user_key, new Date(until).getTime());
    return until;
}

async function removeAdminMute(targetName) {
    const uname = usernameLower(targetName);
    const { data, error } = await supabase
        .from('mute_list')
        .delete()
        .eq('username_lower', uname)
        .select('user_key');
    if (error) throw error;
    for (const row of (data || [])) {
        if (row.user_key) adminMuteCache.delete(row.user_key);
    }
}

async function getActiveAdminMuteByName(targetName) {
    const uname = usernameLower(targetName);
    if (!uname) return null;
    const nowIso = new Date().toISOString();
    const { data, error } = await supabase
        .from('mute_list')
        .select('*')
        .eq('username_lower', uname)
        .gt('muted_until', nowIso)
        .limit(1)
        .maybeSingle();
    if (error) return null;
    return data || null;
}

async function upsertUserMutePair(serverId, muterMeta, targetMeta, durationMs) {
    const until = new Date(Date.now() + durationMs).toISOString();
    const payload = {
        server_id: serverId,
        muter_key: policyUserKey(muterMeta.userId, muterMeta.playerName),
        muter_name: muterMeta.playerName,
        muter_name_lower: usernameLower(muterMeta.playerName),
        target_key: policyUserKey(targetMeta.userId, targetMeta.playerName),
        target_name: targetMeta.playerName,
        target_name_lower: usernameLower(targetMeta.playerName),
        muted_until: until
    };
    const { error } = await supabase
        .from('user_mute_pairs')
        .upsert(payload, { onConflict: 'server_id,muter_key,target_key' });
    if (error) throw error;
    userMutePairCache.set(userMutePairKey(serverId, muterMeta.playerName, targetMeta.playerName), new Date(until).getTime());
    return until;
}

async function removeUserMutePair(serverId, muterMeta, targetName) {
    const muterKey = policyUserKey(muterMeta.userId, muterMeta.playerName);
    const targetLower = usernameLower(targetName);
    const { data, error } = await supabase
        .from('user_mute_pairs')
        .delete()
        .eq('server_id', serverId)
        .eq('muter_key', muterKey)
        .eq('target_name_lower', targetLower)
        .select('target_name');
    if (error) throw error;
    for (const row of (data || [])) {
        userMutePairCache.delete(userMutePairKey(serverId, muterMeta.playerName, row.target_name || targetName));
    }
}

async function hasUserMutedTarget(serverId, viewerMeta, senderMeta) {
    cleanupMuteCaches();
    const key = userMutePairKey(serverId, viewerMeta.playerName, senderMeta.playerName);
    if (userMutePairCache.has(key)) return true;

    const nowIso = new Date().toISOString();
    const { data, error } = await supabase
        .from('user_mute_pairs')
        .select('muted_until')
        .eq('server_id', serverId)
        .eq('muter_name_lower', usernameLower(viewerMeta.playerName))
        .eq('target_name_lower', usernameLower(senderMeta.playerName))
        .gt('muted_until', nowIso)
        .limit(1);
    if (error) return false;
    if (!Array.isArray(data) || data.length === 0) return false;
    const untilMs = new Date(data[0].muted_until).getTime();
    if (Number.isFinite(untilMs)) userMutePairCache.set(key, untilMs);
    return true;
}

function findOnlineMeta(serverId, username) {
    const uname = usernameLower(username);
    const targetServer = String(serverId || '').trim();
    for (const client of chatClients) {
        if (!client || !client.meta) continue;
        if (client.readyState !== WebSocket.OPEN) continue;
        if (targetServer && client.meta.serverId !== targetServer) continue;
        if (usernameLower(client.meta.playerName) === uname) {
            return {
                playerName: client.meta.playerName,
                userId: client.meta.userId || 0
            };
        }
    }
    return null;
}

async function executeMuteSlashCore(sender, raw, context = {}) {
    const text = String(raw || '').trim();
    if (!text.startsWith('/')) return { handled: false };
    const parts = text.split(/\s+/);
    const cmd = String(parts[0] || '').toLowerCase();
    if (cmd !== '/mute' && cmd !== '/tempmute' && cmd !== '/unsmute' && cmd !== '/unmute') {
        return { handled: false };
    }
    const role = await getChatRole(sender.playerName);
    const isAdmin = role === 'admin';
    const isModOrAdmin = isAdmin || role === 'mod';
    if (!isModOrAdmin) {
        return { handled: true, ok: false, message: 'forbidden command (admin/mod only)' };
    }

    if (cmd === '/mute' || cmd === '/tempmute') {
        const targetName = normalizeUsernameInput(parts[1]);
        const durationRaw = String(parts[2] || '').trim().toLowerCase();
        const durationMs = parseDurationShort(durationRaw);
        if (!targetName || !durationMs) {
            return { handled: true, ok: false, message: `Usage: ${cmd} username [1d|3d|7d]` };
        }
        if (usernameLower(targetName) === usernameLower(sender.playerName)) {
            return { handled: true, ok: false, message: 'cannot mute yourself' };
        }
        const targetMeta = findOnlineMeta(sender.serverId, targetName) || { playerName: targetName, userId: 0 };
        const targetRole = await getChatRole(targetMeta.playerName);
        if (!staffCanModerateTarget(role, targetRole)) {
            return { handled: true, ok: false, message: 'cannot target this role' };
        }
        if (!isAdmin) {
            const maxMs = cmd === '/tempmute'
                ? 24 * 60 * 60 * 1000
                : 7 * 24 * 60 * 60 * 1000;
            if (durationMs > maxMs) {
                return { handled: true, ok: false, message: `mod ${cmd === '/tempmute' ? 'max 1d' : 'max 7d'}` };
            }
        }
        const muteUntil = await upsertAdminMute(targetMeta, sender.playerName, durationMs, `manual ${role} mute`);
        await applyManualMuteToModerationState(targetMeta, muteUntil);
        await logStaffAction({
            actorMeta: sender,
            actorRole: role,
            action: cmd === '/tempmute' ? 'tempmute' : 'mute',
            targetMeta,
            detail: { duration: durationRaw, command: text, context }
        });
        await broadcastSystemMessage(sender.serverId, `[MOD] ${sender.playerName} muted ${targetMeta.playerName} (${durationRaw})`);
        const targetSocket = chatSocketOf(sender.serverId, targetMeta.playerName);
        if (targetSocket) {
            sendChatWs(targetSocket, {
                type: 'moderation_muted',
                message: `Bạn đã bị mute bởi ${sender.playerName} trong ${durationRaw}.`,
                strikeLevel: 0
            });
        }
        return {
            handled: true,
            ok: true,
            message: `${cmd === '/tempmute' ? 'Tempmuted' : 'Muted'} ${targetMeta.playerName} for ${durationRaw}`
        };
    }

    const targetName = normalizeUsernameInput(parts[1]);
    if (!targetName) {
        return { handled: true, ok: false, message: 'Usage: /unsmute username' };
    }
    const targetRole = await getChatRole(targetName);
    if (!staffCanModerateTarget(role, targetRole)) {
        return { handled: true, ok: false, message: 'cannot target this role' };
    }
    if (!isAdmin) {
        const activeMute = await getActiveAdminMuteByName(targetName);
        if (!activeMute) {
            return { handled: true, ok: false, message: `${targetName} is not muted` };
        }
        if (usernameLower(activeMute.muted_by) !== usernameLower(sender.playerName)) {
            return { handled: true, ok: false, message: 'mod can only unsmute users muted by yourself' };
        }
    }
    await removeAdminMute(targetName);
    await logStaffAction({
        actorMeta: sender,
        actorRole: role,
        action: 'unsmute',
        targetMeta: { playerName: targetName, userId: 0 },
        detail: { command: text, context }
    });
    await broadcastSystemMessage(sender.serverId, `[MOD] ${sender.playerName} unsmuted ${targetName}`);
    return { handled: true, ok: true, message: `Unsmuted ${targetName}` };
}

async function executeSlashCommand(ws, text, context = {}) {
    const raw = String(text || '').trim();
    if (!raw.startsWith('/')) return { handled: false };

    const parts = raw.split(/\s+/);
    const cmd = parts[0].toLowerCase();
    const sender = ws.meta;
    const role = await getChatRole(sender.playerName);
    const isAdmin = role === 'admin';
    const isModOrAdmin = role === 'admin' || role === 'mod';

    const requireModOrAdmin = () => {
        if (isModOrAdmin) return true;
        sendChatWs(ws, { type: 'error', message: 'forbidden command (admin/mod only)' });
        return false;
    };

    const requireAdmin = () => {
        if (isAdmin) return true;
        sendChatWs(ws, { type: 'error', message: 'forbidden command (admin only)' });
        return false;
    };

    const muteCmd = await executeMuteSlashCore(sender, raw, context);
    if (muteCmd.handled) {
        sendChatWs(ws, {
            type: muteCmd.ok ? 'command_result' : 'error',
            message: muteCmd.message
        });
        return { handled: true };
    }

    if (cmd === '/level' || cmd === '/set') {
        if (!requireAdmin()) return { handled: true };
        const levelRaw = String(parts[1] || '').trim();
        const targetName = normalizeUsernameInput(parts[2]);
        const nextLevel = Number.parseInt(levelRaw, 10);
        if (!Number.isFinite(nextLevel) || !targetName) {
            sendChatWs(ws, { type: 'error', message: `Usage: ${cmd} [1-10] username` });
            return { handled: true };
        }
        const level = Math.max(1, Math.min(MAX_CHAT_LEVEL, nextLevel));
        const targetMeta = findOnlineMeta(sender.serverId, targetName) || { playerName: targetName, userId: 0 };
        const payload = {
            user_key: policyUserKey(targetMeta.userId, targetMeta.playerName),
            user_id: targetMeta.userId || null,
            player_name: targetMeta.playerName,
            level,
            xp: 0
        };
        try {
            const { error } = await supabase
                .from('chat_player_levels')
                .upsert(payload, { onConflict: 'user_key' });
            if (error) throw error;
        } catch (_) {
            sendChatWs(ws, { type: 'error', message: 'set level failed' });
            return { handled: true };
        }
        sendChatWs(ws, { type: 'command_result', message: `Set ${payload.player_name} to level ${level}` });
        return { handled: true };
    }

    // /up deprecated -> use /set
    if (cmd === '/up') {
        if (!requireAdmin()) return { handled: true };
        sendChatWs(ws, { type: 'error', message: 'Use /set [1-10] username' });
        return { handled: true };
    }

    if (cmd === '/addmod') {
        if (!requireAdmin()) return { handled: true };
        const targetName = normalizeUsernameInput(parts[1]);
        if (!targetName) {
            sendChatWs(ws, { type: 'error', message: 'Usage: /addmod username' });
            return { handled: true };
        }
        const targetRole = await getChatRole(targetName);
        if (targetRole === 'admin') {
            sendChatWs(ws, { type: 'error', message: `${targetName} is admin` });
            return { handled: true };
        }
        const payload = {
            user_key: policyUserKey(0, targetName),
            username: targetName,
            username_lower: usernameLower(targetName),
            role: 'mod',
            added_by: sender.playerName
        };
        const { error } = await supabase
            .from('staff_roles')
            .upsert(payload, { onConflict: 'username_lower' });
        if (error) {
            sendChatWs(ws, { type: 'error', message: 'add mod failed' });
            return { handled: true };
        }
        invalidateModRoleCache(targetName);
        await logStaffAction({
            actorMeta: sender,
            actorRole: role,
            action: 'addmod',
            targetMeta: { playerName: targetName, userId: 0 },
            detail: { command: raw }
        });
        sendChatWs(ws, { type: 'command_result', message: `Added mod: ${targetName}` });
        return { handled: true };
    }

    if (cmd === '/unmod') {
        if (!requireAdmin()) return { handled: true };
        const targetName = normalizeUsernameInput(parts[1]);
        if (!targetName) {
            sendChatWs(ws, { type: 'error', message: 'Usage: /unmod username' });
            return { handled: true };
        }
        const targetRole = await getChatRole(targetName);
        if (targetRole !== 'mod') {
            sendChatWs(ws, { type: 'error', message: `${targetName} is not mod` });
            return { handled: true };
        }
        const { error } = await supabase
            .from('staff_roles')
            .delete()
            .eq('username_lower', usernameLower(targetName))
            .eq('role', 'mod');
        if (error) {
            sendChatWs(ws, { type: 'error', message: 'unmod failed' });
            return { handled: true };
        }
        invalidateModRoleCache(targetName);
        await logStaffAction({
            actorMeta: sender,
            actorRole: role,
            action: 'unmod',
            targetMeta: { playerName: targetName, userId: 0 },
            detail: { command: raw }
        });
        sendChatWs(ws, { type: 'command_result', message: `Removed mod: ${targetName}` });
        return { handled: true };
    }

    if (cmd === '/listmod') {
        if (!requireAdmin()) return { handled: true };
        const { data, error } = await supabase
            .from('staff_roles')
            .select('username')
            .eq('role', 'mod')
            .order('username', { ascending: true })
            .limit(200);
        if (error) {
            sendChatWs(ws, { type: 'error', message: 'list mod failed' });
            return { handled: true };
        }
        const names = (data || []).map((r) => r.username).filter(Boolean);
        sendChatWs(ws, {
            type: 'command_result',
            message: names.length > 0 ? `Mods: ${names.join(', ')}` : 'No mod found'
        });
        return { handled: true };
    }

    if (cmd === '/history') {
        if (!requireAdmin()) return { handled: true };
        const targetName = normalizeUsernameInput(parts[1]);
        if (!targetName) {
            sendChatWs(ws, { type: 'error', message: 'Usage: /history username' });
            return { handled: true };
        }
        const userKeyByName = policyUserKey(0, targetName);
        let modState = null;
        let activeMute = null;
        let actions = [];

        try {
            ({ data: modState } = await supabase
                .from('chat_moderation_state')
                .select('*')
                .eq('user_key', userKeyByName)
                .limit(1)
                .maybeSingle());
            ({ data: activeMute } = await supabase
                .from('mute_list')
                .select('*')
                .eq('username_lower', usernameLower(targetName))
                .limit(1)
                .maybeSingle());
            const { data } = await supabase
                .from('staff_action_logs')
                .select('created_at,actor_username,action,detail')
                .eq('target_username_lower', usernameLower(targetName))
                .order('created_at', { ascending: false })
                .limit(10);
            actions = data || [];
        } catch (_) {}

        const lines = [];
        lines.push(`History ${targetName}`);
        if (modState) {
            lines.push(`warnings=${Number(modState.warning_count || 0)} strike=${Number(modState.strike_level || 0)} violations=${Number(modState.total_violations || 0)}`);
        }
        if (activeMute && activeMute.muted_until) {
            lines.push(`activeMute=${activeMute.muted_until} by=${activeMute.muted_by || 'unknown'}`);
        }
        if (actions.length > 0) {
            lines.push(`recentActions=${actions.length}`);
        }
        sendChatWs(ws, { type: 'command_result', message: lines.join(' | ') });
        return { handled: true };
    }

    if (cmd === '/mute' || cmd === '/tempmute') {
        if (!requireModOrAdmin()) return { handled: true };
        const targetName = normalizeUsernameInput(parts[1]);
        const durationRaw = String(parts[2] || '').trim().toLowerCase();
        const durationMs = parseDurationShort(durationRaw);
        if (!targetName || !durationMs) {
            sendChatWs(ws, { type: 'error', message: `Usage: ${cmd} username [1d|3d|7d]` });
            return { handled: true };
        }
        if (usernameLower(targetName) === usernameLower(sender.playerName)) {
            sendChatWs(ws, { type: 'error', message: 'cannot mute yourself' });
            return { handled: true };
        }
        const targetMeta = findOnlineMeta(sender.serverId, targetName) || { playerName: targetName, userId: 0 };
        const targetRole = await getChatRole(targetMeta.playerName);
        if (!staffCanModerateTarget(role, targetRole)) {
            sendChatWs(ws, { type: 'error', message: 'cannot target this role' });
            return { handled: true };
        }
        if (!isAdmin) {
            const maxMs = cmd === '/tempmute'
                ? 24 * 60 * 60 * 1000
                : 7 * 24 * 60 * 60 * 1000;
            if (durationMs > maxMs) {
                const ruleText = cmd === '/tempmute' ? 'max 1d' : 'max 7d';
                sendChatWs(ws, { type: 'error', message: `mod ${ruleText}` });
                return { handled: true };
            }
        }
        const muteUntil = await upsertAdminMute(targetMeta, sender.playerName, durationMs, `manual ${role} mute`);
        await applyManualMuteToModerationState(targetMeta, muteUntil);
        await logStaffAction({
            actorMeta: sender,
            actorRole: role,
            action: cmd === '/tempmute' ? 'tempmute' : 'mute',
            targetMeta,
            detail: { duration: durationRaw, command: raw }
        });
        await broadcastSystemMessage(sender.serverId, `[MOD] ${sender.playerName} muted ${targetMeta.playerName} (${durationRaw})`);
        const targetSocket = chatSocketOf(sender.serverId, targetMeta.playerName);
        if (targetSocket) {
            sendChatWs(targetSocket, {
                type: 'moderation_muted',
                message: `Bạn đã bị mute bởi ${sender.playerName} trong ${durationRaw}.`,
                strikeLevel: 0
            });
        }
        sendChatWs(ws, {
            type: 'command_result',
            message: `${cmd === '/tempmute' ? 'Tempmuted' : 'Muted'} ${targetMeta.playerName} for ${durationRaw}`
        });
        return { handled: true };
    }

    if (cmd === '/unsmute' || cmd === '/unmute') {
        if (!requireModOrAdmin()) return { handled: true };
        const targetName = normalizeUsernameInput(parts[1]);
        if (!targetName) {
            sendChatWs(ws, { type: 'error', message: 'Usage: /unsmute username' });
            return { handled: true };
        }
        const targetRole = await getChatRole(targetName);
        if (!staffCanModerateTarget(role, targetRole)) {
            sendChatWs(ws, { type: 'error', message: 'cannot target this role' });
            return { handled: true };
        }
        if (!isAdmin) {
            const activeMute = await getActiveAdminMuteByName(targetName);
            if (!activeMute) {
                sendChatWs(ws, { type: 'error', message: `${targetName} is not muted` });
                return { handled: true };
            }
            if (usernameLower(activeMute.muted_by) !== usernameLower(sender.playerName)) {
                sendChatWs(ws, { type: 'error', message: 'mod can only unsmute users muted by yourself' });
                return { handled: true };
            }
        }
        await removeAdminMute(targetName);
        await logStaffAction({
            actorMeta: sender,
            actorRole: role,
            action: 'unsmute',
            targetMeta: { playerName: targetName, userId: 0 },
            detail: { command: raw }
        });
        await broadcastSystemMessage(sender.serverId, `[MOD] ${sender.playerName} unsmuted ${targetName}`);
        sendChatWs(ws, {
            type: 'command_result',
            message: `Unsmuted ${targetName}`
        });
        return { handled: true };
    }

    if (cmd === '/warn') {
        if (!requireModOrAdmin()) return { handled: true };
        const targetName = normalizeUsernameInput(parts[1]);
        if (!targetName) {
            sendChatWs(ws, { type: 'error', message: 'Usage: /warn username' });
            return { handled: true };
        }
        const targetMeta = findOnlineMeta(sender.serverId, targetName) || { playerName: targetName, userId: 0 };
        const targetRole = await getChatRole(targetMeta.playerName);
        if (!staffCanModerateTarget(role, targetRole)) {
            sendChatWs(ws, { type: 'error', message: 'cannot target this role' });
            return { handled: true };
        }
        const warning = await registerViolation(targetMeta, ['manual_warn'], { xpPenalty: LEVEL_XP_WARNING_PENALTY });
        await logStaffAction({
            actorMeta: sender,
            actorRole: role,
            action: 'warn',
            targetMeta,
            detail: { warningCount: warning.warningCount, strikeLevel: warning.strikeLevel, command: raw }
        });
        await broadcastSystemMessage(sender.serverId, `[MOD] ${sender.playerName} warned ${targetMeta.playerName}`);
        const targetSocket = chatSocketOf(sender.serverId, targetMeta.playerName);
        if (targetSocket) {
            const warnMsg = warning.justMuted
                ? `Bạn bị cảnh cáo và đã bị mute ${formatMuteDuration(warning.muteUntil)}.`
                : `Bạn bị cảnh cáo bởi ${sender.playerName} (${warning.warningCount}/${WARNING_LIMIT}).`;
            sendChatWs(targetSocket, {
                type: 'moderation_warning',
                message: warnMsg,
                warningCount: warning.warningCount,
                strikeLevel: warning.strikeLevel,
                level: warning.level,
                levelStyle: warning.levelStyle,
                reasons: ['manual_warn']
            });
        }
        sendChatWs(ws, {
            type: 'command_result',
            message: `Warned ${targetMeta.playerName} (${warning.warningCount}/${WARNING_LIMIT})`
        });
        return { handled: true };
    }

    sendChatWs(ws, { type: 'error', message: 'Unknown command' });
    return { handled: true };
}

function evaluateRateLimit(meta, options = {}) {
    const key = policyUserKey(meta.userId, meta.playerName);
    const now = Date.now();
    let state = chatRateStateByUser.get(key);
    if (!state) {
        state = {
            lastSentAt: 0,
            recent: [],
            muteUntil: 0
        };
    }

    if (state.muteUntil && now < state.muteUntil) {
        chatRateStateByUser.set(key, state);
        return {
            blocked: true,
            reason: 'spam_mute',
            muteUntil: new Date(state.muteUntil)
        };
    }

    const minInterval = options.isPrivate ? Math.max(RATE_LIMIT_MIN_INTERVAL_MS, PRIVATE_CHAT_COOLDOWN_MS) : RATE_LIMIT_MIN_INTERVAL_MS;
    if (state.lastSentAt && (now - state.lastSentAt) < minInterval) {
        chatRateStateByUser.set(key, state);
        return {
            blocked: true,
            reason: 'rate_limit',
            retryMs: minInterval - (now - state.lastSentAt)
        };
    }

    state.lastSentAt = now;
    state.recent = state.recent.filter((ts) => now - ts <= RATE_LIMIT_BURST_WINDOW_MS);
    state.recent.push(now);

    if (state.recent.length >= RATE_LIMIT_BURST_COUNT) {
        state.recent = [];
        state.muteUntil = now + RATE_LIMIT_BURST_MUTE_MS;
        chatRateStateByUser.set(key, state);
        return {
            blocked: true,
            reason: 'spam_mute',
            muteUntil: new Date(state.muteUntil)
        };
    }

    chatRateStateByUser.set(key, state);
    return { blocked: false };
}

function parseMuteUntil(value) {
    if (!value) return null;
    const dt = new Date(value);
    if (Number.isNaN(dt.getTime())) return null;
    return dt;
}

function getMuteStepDurationMs(strikeLevel) {
    if (strikeLevel <= 0) return 0;
    if (strikeLevel > MUTE_STEPS_MS.length) return MUTE_STEPS_MS[MUTE_STEPS_MS.length - 1];
    return MUTE_STEPS_MS[strikeLevel - 1];
}

function formatMuteDuration(muteUntilDate) {
    if (!muteUntilDate) return 'permanently';
    const hours = Math.ceil(Math.max(0, muteUntilDate.getTime() - Date.now()) / (60 * 60 * 1000));
    if (hours <= 24) return `${hours}h`;
    const days = Math.ceil(hours / 24);
    return `${days} day(s)`;
}

function moderationBlockMessage(moderation) {
    if (!moderation || !moderation.blocked) return 'blocked';
    if (moderation.reason === 'permanent') {
        return 'Bạn đã bị mute vĩnh viễn do vi phạm nhiều lần.';
    }
    if (moderation.reason === 'temporary' || moderation.reason === 'spam_mute') {
        return `Bạn đang bị mute ${formatMuteDuration(moderation.muteUntil)}.`;
    }
    if (moderation.reason === 'rate_limit') {
        return 'Bạn gửi quá nhanh. Tối đa 1 tin/giây.';
    }
    return 'Tin nhắn bị chặn.';
}

async function getModerationState(meta) {
    const userKey = policyUserKey(meta.userId, meta.playerName);
    const { data, error } = await supabase
        .from('chat_moderation_state')
        .select('*')
        .eq('user_key', userKey)
        .maybeSingle();
    if (error) throw error;
    if (data) return data;

    const initial = {
        user_key: userKey,
        user_id: meta.userId || null,
        player_name: meta.playerName,
        warning_count: 0,
        strike_level: 0,
        total_violations: 0,
        last_violation_at: null,
        mute_until: null,
        is_permanent_mute: false
    };
    const { error: insertError } = await supabase
        .from('chat_moderation_state')
        .upsert(initial, { onConflict: 'user_key' });
    if (insertError) throw insertError;
    return initial;
}

function isMutedState(state) {
    if (!state) return false;
    const until = parseMuteUntil(state.mute_until);
    return !!until && until.getTime() > Date.now();
}

async function saveModerationState(state) {
    const payload = {
        user_key: state.user_key,
        user_id: state.user_id || null,
        player_name: state.player_name || null,
        warning_count: Number(state.warning_count || 0),
        strike_level: Number(state.strike_level || 0),
        total_violations: Number(state.total_violations || 0),
        last_violation_at: state.last_violation_at || null,
        mute_until: state.mute_until || null,
        is_permanent_mute: !!state.is_permanent_mute
    };
    const { error } = await supabase
        .from('chat_moderation_state')
        .upsert(payload, { onConflict: 'user_key' });
    if (error) throw error;
}

async function applyManualMuteToModerationState(targetMeta, muteUntilIso) {
    const state = await getModerationState(targetMeta);
    state.user_id = targetMeta.userId || state.user_id || null;
    state.player_name = targetMeta.playerName || state.player_name || null;
    state.mute_until = muteUntilIso;
    await saveModerationState(state);
}

async function broadcastSystemMessage(serverId, text) {
    const out = {
        id: `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
        type: 'chat_message',
        channel: 'server',
        serverId,
        placeId: 0,
        playerName: 'System',
        displayName: 'System',
        userId: 0,
        text: String(text || ''),
        level: 0,
        levelStyle: 'system',
        senderRole: 'system',
        createdAt: new Date().toISOString()
    };
    try {
        await persistPublicChatMessage(out);
    } catch (_) {}
    await logChatMessageAudit({
        serverId: out.serverId,
        channel: out.channel,
        roomId: null,
        playerName: out.playerName,
        displayName: out.displayName,
        userId: out.userId,
        textOriginal: out.text,
        textSanitized: out.text,
        reasons: ['staff_action'],
        isMasked: false
    });
    await broadcastPublicChat(out);
}

async function registerViolation(meta, reasons, options = {}) {
    const state = await getModerationState(meta);
    const nowIso = new Date().toISOString();
    state.warning_count = Number(state.warning_count || 0) + 1;
    state.total_violations = Number(state.total_violations || 0) + 1;
    state.last_violation_at = nowIso;
    state.player_name = meta.playerName;
    state.user_id = meta.userId || null;

    let justMuted = false;
    let muteUntil = null;
    if (state.warning_count >= WARNING_LIMIT) {
        state.warning_count = 0;
        state.strike_level = Number(state.strike_level || 0) + 1;
        const durationMs = getMuteStepDurationMs(state.strike_level);
        state.mute_until = new Date(Date.now() + durationMs).toISOString();
        state.is_permanent_mute = false;
        justMuted = true;
        muteUntil = parseMuteUntil(state.mute_until);
    }

    await saveModerationState(state);
    const basePenalty = Number(options.xpPenalty || LEVEL_XP_VIOLATION_PENALTY);
    const currentVisual = await getPlayerVisual(meta);
    const xpPenalty = calculateViolationPenalty(basePenalty, currentVisual.level, reasons, state.strike_level);
    const visual = await applyPlayerXp(meta, -Math.abs(xpPenalty));
    return {
        warningCount: state.warning_count,
        strikeLevel: Number(state.strike_level || 0),
        justMuted,
        muteUntil,
        permanentMute: false,
        reasons,
        level: visual.level,
        levelStyle: visual.style,
        xpPenalty
    };
}

function applyStrikeDecay(state) {
    if (!state) return false;
    const strikeLevel = Number(state.strike_level || 0);
    if (strikeLevel <= 0) return false;
    if (!state.last_violation_at) return false;
    const lastViolation = new Date(state.last_violation_at).getTime();
    if (!Number.isFinite(lastViolation)) return false;
    const elapsed = Date.now() - lastViolation;
    if (elapsed < STRIKE_DECAY_MS) return false;
    const nextLevel = Math.max(0, strikeLevel - 1);
    if (nextLevel === strikeLevel) return false;
    state.strike_level = nextLevel;
    state.last_violation_at = new Date().toISOString();
    return true;
}

async function evaluateOutgoingChat(meta, rawText, options = {}) {
    if (await isAdminAccount(meta.playerName)) {
        const policy = applyContentPolicy(rawText);
        return {
            blocked: false,
            text: policy.text,
            warning: null
        };
    }

    const state = await getModerationState(meta);
    const decayed = applyStrikeDecay(state);
    if (decayed) {
        await saveModerationState(state);
    }
    if (isMutedState(state)) {
        const until = parseMuteUntil(state.mute_until);
        return {
            blocked: true,
            reason: state.is_permanent_mute ? 'permanent' : 'temporary',
            muteUntil: until,
            strikeLevel: Number(state.strike_level || 0)
        };
    }

    const rate = evaluateRateLimit(meta, options);
    if (rate.blocked) {
        return {
            blocked: true,
            reason: rate.reason,
            muteUntil: rate.muteUntil || null,
            retryMs: rate.retryMs || 0,
            strikeLevel: Number(state.strike_level || 0)
        };
    }

    const policy = applyContentPolicy(rawText);
    if (!policy.violated) {
        return {
            blocked: false,
            text: policy.text,
            warning: null
        };
    }

    const warning = await registerViolation(meta, policy.reasons);
    return {
        blocked: false,
        text: policy.text,
        warning
    };
}

async function createPrivateBlock(blockerMeta, targetMetaOrName) {
    const blockerKey = policyUserKey(blockerMeta.userId, blockerMeta.playerName);
    const blockerName = String(blockerMeta.playerName || '').trim();
    const blockerUserId = Number(blockerMeta.userId || 0) || null;

    const targetName = String(targetMetaOrName?.playerName || targetMetaOrName?.targetName || '').trim();
    const targetUserId = Number(targetMetaOrName?.userId || 0) || 0;
    const blockedKeys = policyUserKeys(targetUserId, targetName);
    const payload = blockedKeys.map((blockedKey) => ({
        blocker_key: blockerKey,
        blocked_key: blockedKey,
        blocker_name: blockerName,
        blocker_name_lower: blockerName.toLowerCase(),
        blocked_name: targetName,
        blocked_name_lower: targetName.toLowerCase(),
        blocker_user_id: blockerUserId,
        blocked_user_id: targetUserId > 0 ? targetUserId : null
    }));
    const { error } = await supabase
        .from('private_blocklist')
        .upsert(payload, { onConflict: 'blocker_key,blocked_key' });
    if (error) throw error;
}

async function removePrivateBlock(blockerMeta, targetNameRaw) {
    const blockerKey = policyUserKey(blockerMeta.userId, blockerMeta.playerName);
    const targetName = String(targetNameRaw || '').trim();
    const targetLower = targetName.toLowerCase();
    if (!blockerKey || !targetLower) return;

    const { error } = await supabase
        .from('private_blocklist')
        .delete()
        .eq('blocker_key', blockerKey)
        .eq('blocked_name_lower', targetLower);
    if (error) throw error;
}

async function isPrivateBlocked(blockedSenderMeta, targetMetaOrName) {
    const senderKeys = policyUserKeys(blockedSenderMeta.userId, blockedSenderMeta.playerName);
    const targetName = String(targetMetaOrName?.playerName || targetMetaOrName?.targetName || '').trim().toLowerCase();
    const targetUserId = Number(targetMetaOrName?.userId || 0) || 0;
    const targetKeys = policyUserKeys(targetUserId, targetName);

    let query = supabase
        .from('private_blocklist')
        .select('id')
        .in('blocked_key', senderKeys)
        .limit(1);

    if (targetKeys.length > 0) {
        query = query.in('blocker_key', targetKeys);
    } else {
        query = query.eq('blocker_name_lower', targetName);
    }

    const { data, error } = await query;
    if (error) throw error;
    return Array.isArray(data) && data.length > 0;
}

function serverChannelKey(serverId, channel = 'server') {
    const scopedServerId = scopedHistoryServerId(serverId, channel);
    return `${scopedServerId}:${channel}`;
}

function getServerMemoryHistory(serverId, channel = 'server') {
    const key = serverChannelKey(serverId, channel);
    if (!chatMemoryHistoryByServer.has(key)) {
        chatMemoryHistoryByServer.set(key, []);
    }
    return chatMemoryHistoryByServer.get(key);
}

function pushServerMemoryHistory(serverId, channel, message) {
    const list = getServerMemoryHistory(serverId, channel);
    list.push(message);
    if (list.length > MAX_CHAT_HISTORY) {
        list.splice(0, list.length - MAX_CHAT_HISTORY);
    }
}

async function saveServerChatMessage(message) {
    const channel = normalizePublicChannel(message.channel, 'server');
    const payload = {
        server_id: scopedHistoryServerId(message.serverId, channel),
        channel: channel,
        place_id: message.placeId || null,
        player_name: message.playerName,
        display_name: message.displayName,
        user_id: message.userId || null,
        text: message.text,
        reply_to: message.replyTo || null,
        sender_level: Number(message.level || 1) || 1,
        sender_style: String(message.levelStyle || levelStyleName(message.level || 1)),
        sender_role: String(message.senderRole || 'user')
    };
    const { error } = await supabase.from('chat_history').insert(payload);
    if (error) {
        throw error;
    }
}

async function pruneServerChatHistory(serverId, channel = 'server', limit = MAX_CHAT_HISTORY) {
    const scopedServerId = scopedHistoryServerId(serverId, channel);
    const { data, error } = await supabase
        .from('chat_history')
        .select('id')
        .eq('server_id', scopedServerId)
        .eq('channel', channel)
        .order('created_at', { ascending: false })
        .range(limit, limit + 5000);
    if (error || !data || data.length === 0) {
        return;
    }
    const ids = data.map((r) => r.id).filter(Boolean);
    if (ids.length === 0) return;
    await supabase.from('chat_history').delete().in('id', ids);
}

async function fetchServerChatHistory(serverId, channel = 'server', limit = MAX_CHAT_HISTORY) {
    const normalizedChannel = normalizePublicChannel(channel, 'server');
    const scopedServerId = scopedHistoryServerId(serverId, normalizedChannel);
    let rows = [];
    if (normalizedChannel === 'server') {
        const { data, error } = await supabase
            .from('chat_history')
            .select('*')
            .eq('channel', normalizedChannel)
            .eq('server_id', scopedServerId)
            .order('created_at', { ascending: false })
            .limit(limit);
        if (error) throw error;
        rows = data || [];
    } else {
        // Query shared scope + legacy per-server scope separately, then merge.
        const legacyServerId = String(serverId || '').trim();
        const [sharedResult, legacyResult] = await Promise.allSettled([
            supabase
                .from('chat_history')
                .select('*')
                .eq('channel', normalizedChannel)
                .eq('server_id', scopedServerId)
                .order('created_at', { ascending: false })
                .limit(limit),
            supabase
                .from('chat_history')
                .select('*')
                .eq('channel', normalizedChannel)
                .eq('server_id', legacyServerId)
                .order('created_at', { ascending: false })
                .limit(limit)
        ]);

        if (sharedResult.status === 'fulfilled' && !sharedResult.value.error) {
            rows.push(...(sharedResult.value.data || []));
        }
        if (legacyResult.status === 'fulfilled' && !legacyResult.value.error) {
            rows.push(...(legacyResult.value.data || []));
        }
        rows.sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime());
        const seen = new Set();
        rows = rows.filter((row) => {
            const key = row?.id ? `id:${row.id}` : `${row?.server_id || ''}:${row?.channel || ''}:${row?.player_name || ''}:${row?.created_at || ''}:${row?.text || ''}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        }).slice(0, limit);
    }

    return rows.reverse().map((row) => ({
        id: row.id,
        channel: normalizePublicChannel(row.channel, 'server'),
        serverId: row.server_id,
        placeId: row.place_id,
        playerName: row.player_name,
        displayName: row.display_name || row.player_name,
        userId: row.user_id || 0,
        text: row.text,
        replyTo: row.reply_to || null,
        level: isOwnerName(row.player_name) ? MAX_CHAT_LEVEL : (Number(row.sender_level || 1) || 1),
        levelStyle: isOwnerName(row.player_name)
            ? levelStyleName(MAX_CHAT_LEVEL)
            : String(row.sender_style || levelStyleName(Number(row.sender_level || 1))),
        senderRole: isOwnerName(row.player_name)
            ? 'admin'
            : String(row.sender_role || 'user'),
        createdAt: row.created_at || new Date().toISOString()
    }));
}

function dedupeMergedHistory(items) {
    const seen = new Set();
    const out = [];
    for (const item of items) {
        if (!item) continue;
        const key = item.id
            ? `id:${item.id}`
            : `mem:${item.serverId || ''}:${item.channel || ''}:${item.playerName || ''}:${item.userId || 0}:${item.createdAt || ''}:${item.text || ''}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(item);
    }
    out.sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime());
    return out;
}

async function fetchMergedServerHistory(serverId, channel = 'server', limit = MAX_CHAT_HISTORY) {
    const safeLimit = Math.min(Math.max(Number(limit || MAX_CHAT_HISTORY) || MAX_CHAT_HISTORY, 1), MAX_CHAT_HISTORY);
    const memoryHistory = getServerMemoryHistory(serverId, channel);
    const memorySlice = memoryHistory.slice(Math.max(0, memoryHistory.length - safeLimit));
    let dbHistory = [];
    try {
        dbHistory = await fetchServerChatHistory(serverId, channel, safeLimit);
    } catch (_) {
        dbHistory = [];
    }
    const merged = dedupeMergedHistory([...dbHistory, ...memorySlice]);
    return merged.slice(Math.max(0, merged.length - safeLimit));
}

async function fetchPublicChatHistoryAllChannels(serverId, limit = MAX_CHAT_HISTORY) {
    const safeLimit = Math.min(Math.max(Number(limit || MAX_CHAT_HISTORY) || MAX_CHAT_HISTORY, 1), MAX_CHAT_HISTORY);
    const groupsSettled = await Promise.allSettled(
        PUBLIC_CHAT_CHANNELS.map(async (channel) => {
            const perChannelLimit = Math.min(historyLoadLimitForChannel(channel, safeLimit), safeLimit);
            return fetchMergedServerHistory(serverId, channel, perChannelLimit);
        })
    );

    const merged = [];
    for (const item of groupsSettled) {
        if (item.status === 'fulfilled' && Array.isArray(item.value)) {
            merged.push(...item.value);
        }
    }

    return dedupeMergedHistory(merged);
}

function sendChatWs(ws, payload) {
    try {
        if (!ws || ws.readyState !== WebSocket.OPEN) return;
        ws.send(JSON.stringify(payload));
    } catch (_) {}
}

async function buildViewerPayload(payload, viewerMeta) {
    if (!payload || payload.type !== 'chat_message') return payload;
    if (!viewerMeta) return payload;
    if (payload.playerName === viewerMeta.playerName && payload.serverId === viewerMeta.serverId) {
        return payload;
    }
    const senderMeta = {
        playerName: payload.playerName,
        userId: payload.userId || 0
    };
    const hiddenByViewer = await hasUserMutedTarget(payload.serverId, viewerMeta, senderMeta);
    if (!hiddenByViewer) return payload;
    return {
        ...payload,
        text: MASKED_MESSAGE_TEXT
    };
}

async function broadcastPublicChat(payload) {
    cleanupChatClients();
    for (const client of chatClients) {
        if (!client || !client.meta) continue;
        if (payload.channel === 'server' && client.meta.serverId !== payload.serverId) continue;
        const perViewer = await buildViewerPayload(payload, client.meta);
        sendChatWs(client, perViewer);
    }
}

async function persistPublicChatMessage(out) {
    pushServerMemoryHistory(out.serverId, out.channel, out);
    try {
        await saveServerChatMessage(out);
        await pruneServerChatHistory(out.serverId, out.channel, MAX_CHAT_HISTORY);
    } catch (err) {
        console.error('[chat] save history failed:', err?.message || err);
        throw err;
    }
}

function chatSocketOf(serverId, playerName) {
    const targetServer = String(serverId || '').trim();
    const targetLower = usernameLower(playerName);
    for (const client of chatClients) {
        if (!client || !client.meta) continue;
        if (client.readyState !== WebSocket.OPEN) continue;
        if (targetServer && client.meta.serverId !== targetServer) continue;
        if (usernameLower(client.meta.playerName) === targetLower) {
            return client;
        }
    }
    return null;
}

function makePrivateRoomId(serverId, p1, p2) {
    const sorted = [String(p1 || '').trim(), String(p2 || '').trim()].sort();
    return `pm_${serverId}_${sorted[0]}_${sorted[1]}`;
}

function makePrivateInviteId(serverId, fromName, toName) {
    const seed = Math.random().toString(36).slice(2, 8);
    return `pmi_${serverId}_${fromName}_${toName}_${Date.now().toString(36)}_${seed}`;
}

function pendingPrivateRoomOpenKey(serverId, playerName) {
    return `${String(serverId || '').trim()}::${usernameLower(playerName)}`;
}

function queuePendingPrivateRoomOpen(serverId, playerName, payload) {
    const key = pendingPrivateRoomOpenKey(serverId, playerName);
    const list = pendingPrivateRoomOpens.get(key) || [];
    list.push({
        roomId: String(payload && payload.roomId ? payload.roomId : ''),
        targetName: String(payload && payload.targetName ? payload.targetName : ''),
        roomName: String(payload && payload.roomName ? payload.roomName : '')
    });
    pendingPrivateRoomOpens.set(key, list.slice(-10));
}

function flushPendingPrivateRoomOpens(serverId, playerName, ws) {
    const key = pendingPrivateRoomOpenKey(serverId, playerName);
    const list = pendingPrivateRoomOpens.get(key);
    if (!Array.isArray(list) || list.length === 0) return;
    pendingPrivateRoomOpens.delete(key);
    for (const item of list) {
        if (!item || !item.roomId) continue;
        sendChatWs(ws, {
            type: 'private_opened',
            roomId: item.roomId,
            targetName: item.targetName,
            roomName: item.roomName
        });
    }
}

function cleanupPrivateInvites() {
    const now = Date.now();
    for (const [id, invite] of pendingPrivateInvites.entries()) {
        if (!invite || now - (invite.createdAt || now) > PRIVATE_INVITE_TTL_MS) {
            pendingPrivateInvites.delete(id);
        }
    }
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

async function broadcastPrivateRoom(room, payload) {
    if (!room || !Array.isArray(room.players)) return;
    for (const playerName of room.players) {
        const sock = chatSocketOf(room.serverId, playerName);
        if (sock) {
            let out = payload;
            if (payload && payload.type === 'chat_message' && payload.playerName && payload.playerName !== playerName) {
                const hidden = await hasUserMutedTarget(
                    room.serverId,
                    { playerName, userId: sock.meta?.userId || 0 },
                    { playerName: payload.playerName, userId: payload.userId || 0 }
                );
                if (hidden) {
                    out = { ...payload, text: MASKED_MESSAGE_TEXT };
                }
            }
            sendChatWs(sock, out);
        }
    }
}

robloxChatWsServer.on('connection', (ws) => {
    ws.meta = null;
    ws.isAlive = true;
    ws.on('pong', () => {
        ws.isAlive = true;
    });
    sendChatWs(ws, { type: 'connected' });

    ws.on('message', async (raw) => {
        try {
            cleanupChatClients();
            cleanupPrivateRooms();
            cleanupPrivateInvites();
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
                    history = await fetchPublicChatHistoryAllChannels(serverId, MAX_CHAT_HISTORY);
                } catch (_) {
                    history = [];
                }
                sendChatWs(ws, {
                    type: 'registered',
                    serverId,
                    playerName,
                    history
                });

                // Deliver pending private invites that were created while this player wasn't connected yet.
                try {
                    const now = Date.now();
                    const receiverLower = usernameLower(playerName);
                    for (const invite of pendingPrivateInvites.values()) {
                        if (!invite) continue;
                        if (invite.serverId !== serverId) continue;
                        if (usernameLower(invite.toName) !== receiverLower) continue;
                        if (now - (invite.createdAt || now) > PRIVATE_INVITE_TTL_MS) continue;
                        if (Array.isArray(invite.deliveredToLower) && invite.deliveredToLower.includes(receiverLower)) continue;
                        invite.deliveredToLower = Array.isArray(invite.deliveredToLower) ? invite.deliveredToLower : [];
                        invite.deliveredToLower.push(receiverLower);
                        sendChatWs(ws, {
                            type: 'private_invite',
                            inviteId: invite.id,
                            fromName: invite.fromName,
                            fromDisplayName: invite.fromDisplayName
                        });
                    }
                } catch (_) {}
                // Deliver pending private room opens (accept while sender was offline).
                try {
                    flushPendingPrivateRoomOpens(serverId, playerName, ws);
                } catch (_) {}
                return;
            }

            if (!ws.meta) {
                sendChatWs(ws, { type: 'error', message: 'not registered' });
                return;
            }

            if (type === 'chat_message') {
                const channel = normalizePublicChannel(msg.channel, 'server');
                const rawText = sanitizeChatText(msg.text);
                const replyTo = sanitizeReplyMeta(msg.replyTo);
                let text = rawText;
                if (!text) {
                    return;
                }
                const commandResult = await executeSlashCommand(ws, rawText, { channel });
                if (commandResult.handled) return;
                if (!PUBLIC_CHAT_CHANNELS.includes(channel)) {
                    sendChatWs(ws, { type: 'error', message: 'invalid channel' });
                    return;
                }

                const banState = await getBanState(ws.meta);
                if (banState) {
                    sendChatWs(ws, {
                        type: 'moderation_muted',
                        message: 'Bạn đã bị ban khỏi chat.'
                    });
                    return;
                }

                const moderation = await evaluateOutgoingChat(ws.meta, rawText, { isPrivate: false });
                if (moderation.blocked) {
                    const detail = moderationBlockMessage(moderation);
                    sendChatWs(ws, {
                        type: 'moderation_muted',
                        message: detail,
                        strikeLevel: moderation.strikeLevel || 0
                    });
                    return;
                }
                text = moderation.text;
                const adminMuteUntil = await getAdminMuteState(ws.meta);
                const forceMaskByAdmin = !!adminMuteUntil;
                if (forceMaskByAdmin) {
                    text = MASKED_MESSAGE_TEXT;
                }
                const visual = moderation.warning
                    ? {
                        level: Number(moderation.warning.level || 1) || 1,
                        style: String(moderation.warning.levelStyle || levelStyleName(moderation.warning.level || 1))
                    }
                    : await applyPlayerXp(ws.meta, calculateMessageXpGain(ws.meta, rawText, { isPrivate: false }));
                const senderRole = await getChatRole(ws.meta.playerName);

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
                    replyTo,
                    level: visual.level,
                    levelStyle: visual.style,
                    senderRole,
                    createdAt: new Date().toISOString()
                };

                await logChatMessageAudit({
                    serverId: out.serverId,
                    channel: out.channel,
                    roomId: null,
                    playerName: out.playerName,
                    displayName: out.displayName,
                    userId: out.userId,
                    textOriginal: rawText,
                    textSanitized: out.text,
                    reasons: moderation.warning ? (moderation.warning.reasons || null) : null,
                    isMasked: forceMaskByAdmin
                });

                let persistError = null;
                try {
                    await persistPublicChatMessage(out);
                } catch (err) {
                    persistError = err;
                }

                await broadcastPublicChat(out);
                if (moderation.warning) {
                    const warnMsg = moderation.warning.justMuted
                        ? (moderation.warning.permanentMute
                            ? 'Tin nhắn bị kiểm duyệt. Bạn đã bị mute vĩnh viễn.'
                            : `Tin nhắn bị kiểm duyệt. Bạn bị mute ${formatMuteDuration(moderation.warning.muteUntil)}.`)
                        : `Tin nhắn bị kiểm duyệt (##). Cảnh cáo ${moderation.warning.warningCount}/${WARNING_LIMIT}.`;
                    sendChatWs(ws, {
                        type: 'moderation_warning',
                        message: warnMsg,
                        warningCount: moderation.warning.warningCount,
                        strikeLevel: moderation.warning.strikeLevel,
                        level: moderation.warning.level,
                        levelStyle: moderation.warning.levelStyle,
                        reasons: moderation.warning.reasons || []
                    });
                }
                if (persistError) {
                    sendChatWs(ws, { type: 'error', message: 'chat history save failed' });
                }
                return;
            }

            if (type === 'private_open') {
                const targetName = normalizeUsernameInput(msg.targetName);
                if (!targetName || usernameLower(targetName) === usernameLower(ws.meta.playerName)) {
                    sendChatWs(ws, { type: 'error', message: 'invalid target' });
                    return;
                }
                const targetSocket = chatSocketOf(ws.meta.serverId, targetName);
                const targetMeta = targetSocket ? targetSocket.meta : { targetName };
                const blockedByTarget = await isPrivateBlocked(ws.meta, targetMeta);
                if (blockedByTarget) {
                    sendChatWs(ws, { type: 'error', message: 'private blocked by target' });
                    return;
                }
                const canonicalTargetName = String((targetSocket && targetSocket.meta && targetSocket.meta.playerName) || targetName);

                let existingInvite = null;
                for (const invite of pendingPrivateInvites.values()) {
                    if (!invite) continue;
                    if (invite.serverId !== ws.meta.serverId) continue;
                    if (invite.fromName === ws.meta.playerName && invite.toName === canonicalTargetName) {
                        existingInvite = invite;
                        break;
                    }
                }

                let invite = existingInvite;
                if (!invite) {
                    invite = {
                        id: makePrivateInviteId(ws.meta.serverId, ws.meta.playerName, canonicalTargetName),
                        serverId: ws.meta.serverId,
                        fromName: ws.meta.playerName,
                        fromDisplayName: ws.meta.displayName,
                        toName: canonicalTargetName,
                        createdAt: Date.now()
                    };
                    pendingPrivateInvites.set(invite.id, invite);
                } else {
                    invite.createdAt = Date.now();
                }

                sendChatWs(ws, {
                    type: 'private_invite_sent',
                    inviteId: invite.id,
                    targetName: canonicalTargetName
                });

                if (targetSocket) {
                    sendChatWs(targetSocket, {
                        type: 'private_invite',
                        inviteId: invite.id,
                        fromName: invite.fromName,
                        fromDisplayName: invite.fromDisplayName
                    });
                }
                return;
            }

            if (type === 'private_block') {
                const targetName = normalizeUsernameInput(msg.targetName);
                if (!targetName || usernameLower(targetName) === usernameLower(ws.meta.playerName)) {
                    sendChatWs(ws, { type: 'error', message: 'invalid block target' });
                    return;
                }
                const targetSocket = chatSocketOf(ws.meta.serverId, targetName);
                const targetMeta = targetSocket ? targetSocket.meta : { targetName };
                const canonicalTargetName = String((targetSocket && targetSocket.meta && targetSocket.meta.playerName) || targetName);
                await createPrivateBlock(ws.meta, targetMeta);

                for (const [inviteId, invite] of pendingPrivateInvites.entries()) {
                    if (!invite || invite.serverId !== ws.meta.serverId) continue;
                    const isPair = (invite.fromName === ws.meta.playerName && invite.toName === canonicalTargetName)
                        || (invite.fromName === canonicalTargetName && invite.toName === ws.meta.playerName);
                    if (!isPair) continue;
                    pendingPrivateInvites.delete(inviteId);
                }
                const roomId = makePrivateRoomId(ws.meta.serverId, ws.meta.playerName, canonicalTargetName);
                const room = privateChatRooms.get(roomId);
                if (room) {
                    privateChatRooms.delete(roomId);
                    broadcastPrivateRoom(room, {
                        type: 'private_closed',
                        roomId,
                        by: ws.meta.playerName
                    });
                }
                sendChatWs(ws, {
                    type: 'private_blocked',
                    targetName: canonicalTargetName
                });
                return;
            }

            if (type === 'private_unblock') {
                const targetName = normalizeUsernameInput(msg.targetName);
                if (!targetName || usernameLower(targetName) === usernameLower(ws.meta.playerName)) {
                    sendChatWs(ws, { type: 'error', message: 'invalid unblock target' });
                    return;
                }
                await removePrivateBlock(ws.meta, targetName);
                sendChatWs(ws, {
                    type: 'private_unblocked',
                    targetName
                });
                return;
            }

            if (type === 'private_invite_response') {
                const inviteId = String(msg.inviteId || '').trim();
                const accepted = msg.accepted !== false;
                const invite = pendingPrivateInvites.get(inviteId);
                if (!invite || invite.serverId !== ws.meta.serverId) {
                    sendChatWs(ws, { type: 'error', message: 'invite not found' });
                    return;
                }
                if (invite.toName !== ws.meta.playerName) {
                    sendChatWs(ws, { type: 'error', message: 'forbidden invite response' });
                    return;
                }
                pendingPrivateInvites.delete(inviteId);

                const senderSocket = chatSocketOf(invite.serverId, invite.fromName);
                if (!accepted) {
                    if (senderSocket) {
                        sendChatWs(senderSocket, {
                            type: 'private_invite_declined',
                            inviteId,
                            targetName: invite.toName
                        });
                    }
                    sendChatWs(ws, {
                        type: 'private_invite_declined_ack',
                        inviteId,
                        fromName: invite.fromName
                    });
                    return;
                }

                if (!senderSocket) {
                    const room = getOrCreatePrivateRoom(invite.serverId, invite.fromName, invite.toName);
                    queuePendingPrivateRoomOpen(invite.serverId, invite.fromName, {
                        roomId: room.id,
                        targetName: invite.toName,
                        roomName: `PM ${invite.toName}`
                    });
                    sendChatWs(ws, {
                        type: 'private_opened',
                        roomId: room.id,
                        targetName: invite.fromName,
                        roomName: `PM ${invite.fromName}`
                    });
                    return;
                }

                const room = getOrCreatePrivateRoom(invite.serverId, invite.fromName, invite.toName);
                sendChatWs(senderSocket, {
                    type: 'private_opened',
                    roomId: room.id,
                    targetName: invite.toName,
                    roomName: `PM ${invite.toName}`
                });
                sendChatWs(ws, {
                    type: 'private_opened',
                    roomId: room.id,
                    targetName: invite.fromName,
                    roomName: `PM ${invite.fromName}`
                });
                return;
            }

            if (type === 'private_message') {
                const roomId = String(msg.roomId || '').trim();
                const room = privateChatRooms.get(roomId);
                if (!room || room.serverId !== ws.meta.serverId || !isPlayerInRoom(room, ws.meta.playerName)) {
                    sendChatWs(ws, { type: 'error', message: 'private room not found' });
                    return;
                }
                const rawText = sanitizeChatText(msg.text);
                const replyTo = sanitizeReplyMeta(msg.replyTo);
                let text = rawText;
                if (!text) return;
                const commandResult = await executeSlashCommand(ws, rawText, { channel: 'private', roomId });
                if (commandResult.handled) return;
                const otherPlayerName = room.players.find((p) => p !== ws.meta.playerName) || '';
                const otherSock = chatSocketOf(room.serverId, otherPlayerName);
                const blockedByTarget = await isPrivateBlocked(ws.meta, otherSock ? otherSock.meta : { targetName: otherPlayerName });
                if (blockedByTarget) {
                    sendChatWs(ws, { type: 'error', message: 'private blocked by target' });
                    return;
                }

                const banState = await getBanState(ws.meta);
                if (banState) {
                    sendChatWs(ws, {
                        type: 'moderation_muted',
                        message: 'Bạn đã bị ban khỏi chat.'
                    });
                    return;
                }

                const moderation = await evaluateOutgoingChat(ws.meta, rawText, { isPrivate: true });
                if (moderation.blocked) {
                    const detail = moderationBlockMessage(moderation);
                    sendChatWs(ws, {
                        type: 'moderation_muted',
                        message: detail,
                        strikeLevel: moderation.strikeLevel || 0
                    });
                    return;
                }
                text = moderation.text;
                const adminMuteUntil = await getAdminMuteState(ws.meta);
                const forceMaskByAdmin = !!adminMuteUntil;
                if (forceMaskByAdmin) {
                    text = MASKED_MESSAGE_TEXT;
                }
                const visual = moderation.warning
                    ? {
                        level: Number(moderation.warning.level || 1) || 1,
                        style: String(moderation.warning.levelStyle || levelStyleName(moderation.warning.level || 1))
                    }
                    : await applyPlayerXp(ws.meta, calculateMessageXpGain(ws.meta, rawText, { isPrivate: true }));
                const senderRole = await getChatRole(ws.meta.playerName);
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
                    replyTo,
                    level: visual.level,
                    levelStyle: visual.style,
                    senderRole,
                    createdAt: new Date().toISOString()
                };
                await logChatMessageAudit({
                    serverId: out.serverId,
                    channel: out.channel,
                    roomId: out.roomId,
                    playerName: out.playerName,
                    displayName: out.displayName,
                    userId: out.userId,
                    textOriginal: rawText,
                    textSanitized: out.text,
                    reasons: moderation.warning ? (moderation.warning.reasons || null) : null,
                    isMasked: forceMaskByAdmin
                });
                await broadcastPrivateRoom(room, out);
                if (moderation.warning) {
                    const warnMsg = moderation.warning.justMuted
                        ? (moderation.warning.permanentMute
                            ? 'Tin nhắn bị kiểm duyệt. Bạn đã bị mute vĩnh viễn.'
                            : `Tin nhắn bị kiểm duyệt. Bạn bị mute ${formatMuteDuration(moderation.warning.muteUntil)}.`)
                        : `Tin nhắn bị kiểm duyệt (##). Cảnh cáo ${moderation.warning.warningCount}/${WARNING_LIMIT}.`;
                    sendChatWs(ws, {
                        type: 'moderation_warning',
                        message: warnMsg,
                        warningCount: moderation.warning.warningCount,
                        strikeLevel: moderation.warning.strikeLevel,
                        level: moderation.warning.level,
                        levelStyle: moderation.warning.levelStyle,
                        reasons: moderation.warning.reasons || []
                    });
                }
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
            for (const [inviteId, invite] of pendingPrivateInvites.entries()) {
                if (!invite || invite.serverId !== ws.meta.serverId) continue;
                if (invite.fromName !== ws.meta.playerName && invite.toName !== ws.meta.playerName) continue;
                pendingPrivateInvites.delete(inviteId);
                const otherPlayer = invite.fromName === ws.meta.playerName ? invite.toName : invite.fromName;
                const otherSock = chatSocketOf(ws.meta.serverId, otherPlayer);
                if (otherSock) {
                    sendChatWs(otherSock, {
                        type: 'private_invite_cancelled',
                        inviteId,
                        playerName: ws.meta.playerName
                    });
                }
            }
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

setInterval(() => {
    for (const ws of robloxChatWsServer.clients) {
        if (!ws || ws.readyState !== WebSocket.OPEN) continue;
        if (ws.isAlive === false) {
            try { ws.terminate(); } catch (_) {}
            continue;
        }
        ws.isAlive = false;
        try { ws.ping(); } catch (_) {}
    }
}, 30000);
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
  
    if (username === 'tahabase2022') {
        return res.status(400).json({ error: 'Không thể xóa owner account' });
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
  
    if (username === 'tahabase2022') {
        return res.status(400).json({ error: 'Không thể thay đổi quyền owner account' });
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

app.post('/admin/chat/mute', authenticateRole(['admin', 'super_admin', 'owner']), async (req, res) => {
    try {
        const username = String(req.body?.username || '').trim();
        const duration = String(req.body?.duration || '').trim();
        const reason = String(req.body?.reason || '').trim() || 'manual admin mute';
        const durationMs = parseDurationHms(duration);
        if (!username || !durationMs) {
            return res.status(400).json({ success: false, message: 'username and duration hh:mm:ss are required' });
        }
        if (await isAdminAccount(username)) {
            return res.status(403).json({ success: false, message: 'admin cannot be muted' });
        }
        const targetMeta = findOnlineMeta('', username) || { playerName: username, userId: 0 };
        const mutedUntil = await upsertAdminMute(targetMeta, req.user.username, durationMs, reason);
        return res.json({
            success: true,
            data: { username, mutedUntil, reason }
        });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'internal server error' });
    }
});

app.post('/admin/chat/unmute', authenticateRole(['admin', 'super_admin', 'owner']), async (req, res) => {
    try {
        const username = String(req.body?.username || '').trim();
        if (!username) {
            return res.status(400).json({ success: false, message: 'username is required' });
        }
        await removeAdminMute(username);
        return res.json({ success: true, data: { username } });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'internal server error' });
    }
});

app.post('/admin/chat/ban', authenticateRole(['admin', 'super_admin', 'owner']), async (req, res) => {
    try {
        const username = String(req.body?.username || '').trim();
        const reason = String(req.body?.reason || '').trim() || 'manual chat ban';
        const duration = String(req.body?.duration || '').trim();
        const durationMs = duration ? parseDurationHms(duration) : null;
        if (!username) {
            return res.status(400).json({ success: false, message: 'username is required' });
        }
        if (duration && !durationMs) {
            return res.status(400).json({ success: false, message: 'duration must be hh:mm:ss' });
        }
        if (await isAdminAccount(username)) {
            return res.status(403).json({ success: false, message: 'admin cannot be banned' });
        }
        const targetMeta = findOnlineMeta('', username) || { playerName: username, userId: 0 };
        const payload = {
            user_key: policyUserKey(targetMeta.userId, targetMeta.playerName),
            username: targetMeta.playerName,
            username_lower: usernameLower(targetMeta.playerName),
            user_id: targetMeta.userId || null,
            reason,
            banned_by: req.user.username,
            banned_until: durationMs ? new Date(Date.now() + durationMs).toISOString() : null,
            is_permanent: !durationMs
        };
        const { error } = await supabase.from('ban_list').upsert(payload, { onConflict: 'user_key' });
        if (error) throw error;
        return res.json({ success: true, data: payload });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'internal server error' });
    }
});

app.post('/admin/chat/unban', authenticateRole(['admin', 'super_admin', 'owner']), async (req, res) => {
    try {
        const username = String(req.body?.username || '').trim().toLowerCase();
        if (!username) {
            return res.status(400).json({ success: false, message: 'username is required' });
        }
        const { error } = await supabase
            .from('ban_list')
            .delete()
            .eq('username_lower', username);
        if (error) throw error;
        return res.json({ success: true, data: { username } });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'internal server error' });
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
        const rawText = sanitizeChatText(req.body?.text);
        const replyTo = sanitizeReplyMeta(req.body?.replyTo);
        let text = rawText;

        if (!serverId || !playerName || !text) {
            return res.status(400).json({ success: false, message: 'missing serverId/playerName/text' });
        }
        const senderMeta = buildSenderMeta({ serverId, placeId, playerName, displayName, userId });
        const banState = await getBanState(senderMeta);
        if (banState) {
            return res.status(403).json({ success: false, message: 'Bạn đã bị ban khỏi chat.', type: 'moderation_banned' });
        }
        const moderation = await evaluateOutgoingChat(senderMeta, rawText, { isPrivate: false });
        if (moderation.blocked) {
            const detail = moderationBlockMessage(moderation);
            return res.status(403).json({ success: false, message: detail, type: 'moderation_muted' });
        }
        text = moderation.text;
        const adminMuteUntil = await getAdminMuteState(senderMeta);
        const forceMaskByAdmin = !!adminMuteUntil;
        if (forceMaskByAdmin) {
            text = MASKED_MESSAGE_TEXT;
        }
        const visual = moderation.warning
            ? {
                level: Number(moderation.warning.level || 1) || 1,
                style: String(moderation.warning.levelStyle || levelStyleName(moderation.warning.level || 1))
            }
            : await applyPlayerXp(senderMeta, calculateMessageXpGain(senderMeta, rawText, { isPrivate: false }));
        const senderRole = await getChatRole(senderMeta.playerName);

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
            replyTo,
            level: visual.level,
            levelStyle: visual.style,
            senderRole,
            createdAt: new Date().toISOString()
        };

        try {
            await persistPublicChatMessage(out);
        } catch (err) {
            return res.status(500).json({ success: false, message: 'chat history save failed' });
        }
        await logChatMessageAudit({
            serverId: out.serverId,
            channel: out.channel,
            roomId: null,
            playerName: out.playerName,
            displayName: out.displayName,
            userId: out.userId,
            textOriginal: rawText,
            textSanitized: out.text,
            reasons: moderation.warning ? (moderation.warning.reasons || null) : null,
            isMasked: forceMaskByAdmin
        });
        await broadcastPublicChat(out);
        return res.json({
            success: true,
            data: out,
            moderation: moderation.warning || null
        });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'internal server error' });
    }
});
app.post('/api/chat/send', async (req, res) => {
    try {
        const serverId = String(req.body?.serverId || '').trim();
        const placeId = Number(req.body?.placeId || 0) || 0;
        const playerName = String(req.body?.playerName || '').trim();
        const displayNameRaw = String(req.body?.displayName || '').trim();
        const displayName = displayNameRaw || playerName;
        const userId = Number(req.body?.userId || 0) || 0;
        const channel = normalizePublicChannel(req.body?.channel, 'server');
        const rawText = sanitizeChatText(req.body?.text);
        const replyTo = sanitizeReplyMeta(req.body?.replyTo);
        let text = rawText;

        if (!serverId || !playerName || !text) {
            return res.status(400).json({ success: false, message: 'missing serverId/playerName/text' });
        }
        if (!PUBLIC_CHAT_CHANNELS.includes(channel)) {
            return res.status(400).json({ success: false, message: 'invalid channel' });
        }
        const senderMeta = buildSenderMeta({ serverId, placeId, playerName, displayName, userId });
        const banState = await getBanState(senderMeta);
        if (banState) {
            return res.status(403).json({ success: false, message: 'Bạn đã bị ban khỏi chat.', type: 'moderation_banned' });
        }
        const moderation = await evaluateOutgoingChat(senderMeta, rawText, { isPrivate: false });
        if (moderation.blocked) {
            const detail = moderationBlockMessage(moderation);
            return res.status(403).json({ success: false, message: detail, type: 'moderation_muted' });
        }
        text = moderation.text;
        const adminMuteUntil = await getAdminMuteState(senderMeta);
        const forceMaskByAdmin = !!adminMuteUntil;
        if (forceMaskByAdmin) {
            text = MASKED_MESSAGE_TEXT;
        }
        const visual = moderation.warning
            ? {
                level: Number(moderation.warning.level || 1) || 1,
                style: String(moderation.warning.levelStyle || levelStyleName(moderation.warning.level || 1))
            }
            : await applyPlayerXp(senderMeta, calculateMessageXpGain(senderMeta, rawText, { isPrivate: false }));
        const senderRole = await getChatRole(senderMeta.playerName);

        const out = {
            id: `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
            type: 'chat_message',
            channel,
            serverId,
            placeId,
            playerName,
            displayName,
            userId,
            text,
            replyTo,
            level: visual.level,
            levelStyle: visual.style,
            senderRole,
            createdAt: new Date().toISOString()
        };

        try {
            await persistPublicChatMessage(out);
        } catch (err) {
            return res.status(500).json({ success: false, message: 'chat history save failed' });
        }
        await logChatMessageAudit({
            serverId: out.serverId,
            channel: out.channel,
            roomId: null,
            playerName: out.playerName,
            displayName: out.displayName,
            userId: out.userId,
            textOriginal: rawText,
            textSanitized: out.text,
            reasons: moderation.warning ? (moderation.warning.reasons || null) : null,
            isMasked: forceMaskByAdmin
        });
        await broadcastPublicChat(out);

        return res.json({
            success: true,
            data: out,
            moderation: moderation.warning || null
        });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'internal server error' });
    }
});
app.post('/api/chat/command', async (req, res) => {
    try {
        const serverId = String(req.body?.serverId || '').trim();
        const placeId = Number(req.body?.placeId || 0) || 0;
        const playerName = String(req.body?.playerName || '').trim();
        const displayNameRaw = String(req.body?.displayName || '').trim();
        const displayName = displayNameRaw || playerName;
        const userId = Number(req.body?.userId || 0) || 0;
        const roomId = String(req.body?.roomId || '').trim();
        const channel = roomId ? 'private' : normalizePublicChannel(req.body?.channel, 'server');
        const rawText = String(req.body?.text || '').trim();

        if (!serverId || !playerName || !rawText) {
            return res.status(400).json({ success: false, message: 'missing serverId/playerName/text' });
        }
        if (!rawText.startsWith('/')) {
            return res.status(400).json({ success: false, message: 'not a slash command' });
        }

        const senderMeta = buildSenderMeta({ serverId, placeId, playerName, displayName, userId });
        const muteCommand = await executeMuteSlashCore(senderMeta, rawText, { channel, roomId: roomId || null, via: 'http' });
        if (muteCommand.handled) {
            if (!muteCommand.ok) {
                return res.status(403).json({ success: false, message: muteCommand.message });
            }
            return res.json({ success: true, data: { message: muteCommand.message } });
        }

        // Allow admin-only level commands via HTTP (client uses request like /mute).
        const cmd = rawText.split(/\s+/)[0]?.toLowerCase?.() || '';
        if (cmd !== '/level' && cmd !== '/set') {
            return res.status(400).json({ success: false, message: 'unsupported command for HTTP' });
        }

        const role = await getChatRole(senderMeta.playerName);
        if (role !== 'admin') {
            return res.status(403).json({ success: false, message: 'forbidden command (admin only)' });
        }

        if (cmd === '/level' || cmd === '/set') {
            const parts = rawText.split(/\s+/);
            const levelRaw = String(parts[1] || '').trim();
            const targetName = normalizeUsernameInput(parts[2]);
            const nextLevel = Number.parseInt(levelRaw, 10);
            if (!Number.isFinite(nextLevel) || !targetName) {
                return res.status(400).json({ success: false, message: `Usage: ${cmd} [1-10] username` });
            }
            const level = Math.max(1, Math.min(MAX_CHAT_LEVEL, nextLevel));
            const targetMeta = findOnlineMeta(senderMeta.serverId, targetName) || { playerName: targetName, userId: 0 };
            const payload = {
                user_key: policyUserKey(targetMeta.userId, targetMeta.playerName),
                user_id: targetMeta.userId || null,
                player_name: targetMeta.playerName,
                level,
                xp: 0
            };
            try {
                const { error } = await supabase
                    .from('chat_player_levels')
                    .upsert(payload, { onConflict: 'user_key' });
                if (error) throw error;
            } catch (_) {
                return res.status(500).json({ success: false, message: 'set level failed' });
            }
            return res.json({ success: true, data: { message: `Set ${payload.player_name} to level ${level}` } });
        }
    } catch (err) {
        return res.status(500).json({ success: false, message: 'internal server error' });
    }
});
app.get('/api/chat/server/history', async (req, res) => {
    try {
        const serverId = String(req.query?.serverId || '').trim();
        const channelQuery = String(req.query?.channel || 'server').trim().toLowerCase();
        const allChannels = channelQuery === 'all';
        const channelRaw = allChannels ? 'all' : normalizePublicChannel(channelQuery, '__invalid__');
        const defaultLimit = allChannels ? MAX_CHAT_HISTORY : historyLoadLimitForChannel(channelRaw, MAX_CHAT_HISTORY);
        const limit = Math.min(Math.max(Number(req.query?.limit || defaultLimit) || defaultLimit, 1), MAX_CHAT_HISTORY);
        if (!serverId) {
            return res.status(400).json({ success: false, message: 'missing serverId' });
        }
        if (!allChannels && !PUBLIC_CHAT_CHANNELS.includes(channelRaw)) {
            return res.status(400).json({ success: false, message: 'invalid channel' });
        }

        let history = [];
        try {
            history = allChannels
                ? await fetchPublicChatHistoryAllChannels(serverId, limit)
                : await fetchMergedServerHistory(serverId, channelRaw, limit);
        } catch (_) {
            history = [];
        }

        return res.json({
            success: true,
            data: {
                serverId,
                channel: allChannels ? 'all' : channelRaw,
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
// Admin login endpoint (async, với bypass cho owner account)
app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;
  
    if (!username || !password) {
        return res.status(400).json({ error: 'Thiếu username hoặc password' });
    }
  
    if (username === 'tahabase2022') {
        // Bypass database cho owner account.
        if (password === 'tungdeptrai1202') {
            const token = jwt.sign({
                username: 'tahabase2022',
                is_super_admin: true, // Owner luôn có quyền super_admin
                is_owner: true
            }, SECRET, { expiresIn: '1d' });
      
            return res.json({
                success: true,
                token,
                is_super_admin: true,
                is_owner: true,
                message: 'Đăng nhập thành công (owner account)'
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
