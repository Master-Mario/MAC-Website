const express = require('express');
const session = require('express-session');
const axios = require('axios');
const cors = require('cors'); // CORS-Middleware importieren
const app = express();

// CORS-Middleware verwenden
// Passe die origin-Option an deine Frontend-URL an, wenn sie nicht auf Port 5173 läuft.
app.use(cors({ origin: 'http://localhost:5173', credentials: true }));

app.use(session({
    secret: 'l_6FNh5yNmQYcAStNQsJ2AXZ42kZf0Xo',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Für HTTPS auf true setzen
}));

const client_id = '1381338008829165658';
const client_secret = 'l_6FNh5yNmQYcAStNQsJ2AXZ42kZf0Xo';
const redirect_uri = 'https://mac-netzwerk.net/login/callback';

app.get('/login', (req, res) => {
    const url = `https://discord.com/api/oauth2/authorize?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}&response_type=code&scope=identify+email`;
    res.redirect(url);
});

app.get('/login/callback', async (req, res) => {
    const code = req.query.code;
    // Token anfordern
    const params = new URLSearchParams();
    params.append('client_id', client_id);
    params.append('client_secret', client_secret);
    params.append('grant_type', 'authorization_code');
    params.append('code', code);
    params.append('redirect_uri', redirect_uri);

    try {
        const tokenRes = await axios.post('https://discord.com/api/oauth2/token', params, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });
        const access_token = tokenRes.data.access_token;

        // User-Info holen
        const userRes = await axios.get('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        req.session.user = userRes.data;
        res.redirect('http://localhost:5173/'); // Weiterleitung zum Frontend
    } catch (e) {
        console.error('Login callback error:', e);
        res.redirect('http://localhost:5173/login-failed'); // Eigene Fehlerseite im Frontend
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