const express = require('express');
const session = require('express-session');
const axios = require('axios');
const cors = require('cors');
const app = express();

app.set('trust proxy', 1); // Trust first proxy

// Produktions-Konfiguration
const frontend_url = 'https://mac-netzwerk.net';
const discord_redirect_uri = 'https://mac-netzwerk.net/login/callback';

// CORS-Middleware verwenden
app.use(cors({ origin: frontend_url, credentials: true }));

app.use(session({
    secret: process.env.SESSION_SECRET || 'l_6FNh5yNmQYcAStNQsJ2AXZ42kZf0Xo', // UNBEDINGT IN PRODUKTION DURCH EINE SICHERE UMWELTSVARIABLE ERSETZEN!
    resave: false,
    saveUninitialized: false, // Geändert zu false für Produktion
    cookie: {
        secure: true, // In Produktion immer true (HTTPS)
        httpOnly: true,
        sameSite: 'lax',
        path: '/', // Explizit den Cookie-Pfad setzen
        maxAge: 1000 * 60 * 60 * 24 // 1 Tag Lebensdauer für das Cookie
    }
}));

const client_id = process.env.DISCORD_CLIENT_ID || '1381338008829165658'; // Aus Umgebungsvariable laden
const client_secret = process.env.DISCORD_CLIENT_SECRET || 'l_6FNh5yNmQYcAStNQsJ2AXZ42kZf0Xo'; // Aus Umgebungsvariable laden

app.get('/login', (req, res) => {
    const url = `https://discord.com/api/oauth2/authorize?client_id=${client_id}&redirect_uri=${encodeURIComponent(discord_redirect_uri)}&response_type=code&scope=identify+email`;
    res.redirect(url);
});

app.get('/login/callback', async (req, res) => {
    const code = req.query.code;
    if (!code) {
        return res.redirect(frontend_url + '/login-failed.html?error=nocode');
    }
    const params = new URLSearchParams();
    params.append('client_id', client_id);
    params.append('client_secret', client_secret);
    params.append('grant_type', 'authorization_code');
    params.append('code', code);
    params.append('redirect_uri', discord_redirect_uri);

    try {
        const tokenRes = await axios.post('https://discord.com/api/oauth2/token', params, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });
        const access_token = tokenRes.data.access_token;

        const userRes = await axios.get('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        req.session.user = userRes.data;
        // Stelle sicher, dass die Session gespeichert ist, bevor weitergeleitet wird
        req.session.save(err => {
            if (err) {
                console.error('Session save error:', err);
                // Fehlerseite im Frontend mit Parameter für spezifische Fehlermeldung
                return res.redirect(frontend_url + '/login-failed.html?error=session_save_error');
            }
            // Erfolgreiche Weiterleitung zur Homepage im Frontend
            res.redirect(frontend_url + '/');
        });
    } catch (e) {
        console.error('Login callback error:', e.response ? e.response.data : e.message);
        // Fehlerseite im Frontend mit Parameter für spezifische Fehlermeldung
        const errorQuery = e.response && e.response.data && e.response.data.error_description ?
                         `?error=${encodeURIComponent(e.response.data.error_description)}` :
                         '?error=unknown';
        res.redirect(frontend_url + '/login-failed.html' + errorQuery);
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Could not log out.');
        }
        res.clearCookie('connect.sid'); // Cookie löschen, Name kann je nach Session-Store variieren
        res.status(200).send({ message: 'Logged out successfully' });
    });
});

app.get('/api/auth/status', (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
    if (req.session.user) {
        res.json({ loggedIn: true, user: req.session.user });
    } else {
        res.json({ loggedIn: false });
    }
});

app.get('/profile', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    res.send(`Hallo ${req.session.user.username}!`);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server läuft auf Port ${PORT}`));