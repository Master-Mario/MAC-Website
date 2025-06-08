const express = require('express');
const session = require('express-session');
const axios = require('axios');
const cors = require('cors');
const app = express();

// Frontend URLs/ Deine Produktions-Frontend-URL
const frontend_url = 'https://mac-netzwerk.net';

// CORS-Middleware verwenden
app.use(cors({ origin: frontend_url, credentials: true }));

app.use(session({
    secret: process.env.SESSION_SECRET || 'l_6FNh5yNmQYcAStNQsJ2AXZ42kZf0Xo', // Verwende Umgebungsvariable für Secret in Produktion
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: IS_PRODUCTION, // Cookie nur über HTTPS in Produktion senden
        httpOnly: true, // Verhindert Zugriff durch clientseitiges JavaScript
        sameSite: 'lax' // Schutz gegen CSRF
    }
}));

const client_id = process.env.DISCORD_CLIENT_ID || '1381338008829165658';
const client_secret = process.env.DISCORD_CLIENT_SECRET || 'l_6FNh5yNmQYcAStNQsJ2AXZ42kZf0Xo'; // Secrets immer über Env Vars!

// Discord Redirect URIs
const local_discord_redirect_uri = 'http://localhost:3000/login/callback';
const production_discord_redirect_uri = 'https://mac-netzwerk.net/login/callback'; // Passe dies an deine Produktions-Callback-URL an
const discord_redirect_uri = IS_PRODUCTION ? production_discord_redirect_uri : local_discord_redirect_uri;

app.get('/login', (req, res) => {
    const url = `https://discord.com/api/oauth2/authorize?client_id=${client_id}&redirect_uri=${encodeURIComponent(discord_redirect_uri)}&response_type=code&scope=identify+email`;
    res.redirect(url);
});

app.get('/login/callback', async (req, res) => {
    const code = req.query.code;
    const params = new URLSearchParams();
    params.append('client_id', client_id);
    params.append('client_secret', client_secret);
    params.append('grant_type', 'authorization_code');
    params.append('code', code);
    params.append('redirect_uri', discord_redirect_uri); // Verwende die dynamische Discord-Redirect-URI

    try {
        const tokenRes = await axios.post('https://discord.com/api/oauth2/token', params, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });
        const access_token = tokenRes.data.access_token;

        const userRes = await axios.get('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        req.session.user = userRes.data;
        res.redirect(frontend_url + '/'); // Weiterleitung zum dynamischen Frontend
    } catch (e) {
        console.error('Login callback error:', e.response ? e.response.data : e.message);
        res.redirect(frontend_url + '/login-failed.html'); // Weiterleitung zur dynamischen Fehlerseite im Frontend
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

// Route, um den aktuellen Benutzerstatus zu prüfen
app.get('/api/auth/status', (req, res) => {
    if (req.session.user) {
        res.json({ loggedIn: true, user: req.session.user });
    } else {
        res.json({ loggedIn: false });
    }
});

// Beispiel für geschützte Seite
app.get('/profile', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    res.send(`Hallo ${req.session.user.username}!`);
});

app.listen(3000, () => console.log('Server läuft auf Port 3000'));