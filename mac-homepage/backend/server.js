const express = require('express');
const session = require('express-session');
const { createClient } = require('redis');
const RedisStore = require('connect-redis')(session); // angepasst für ältere connect-redis Versionen
const cors = require('cors'); // CORS-Middleware importieren
const axios = require('axios');

const app = express();

// trust proxy Einstellung (wichtig, wenn hinter einem Reverse Proxy wie Nginx)
app.set('trust proxy', 1);

// Produktions-Konfiguration
const frontend_url = 'https://mac-netzwerk.net';
const discord_redirect_uri = 'https://mac-netzwerk.net/login/callback';

// CORS-Konfiguration
// Passen Sie 'http://localhost:5500' an die tatsächliche Adresse Ihres Frontends an.
// Wenn Sie index.html direkt im Browser öffnen (file://), ist dies komplexer.
// Für lokale Entwicklung ist es oft besser, das Frontend über einen lokalen Server (z.B. Live Server in VS Code) bereitzustellen.
app.use(cors({
    origin: ['http://localhost:5500', 'http://127.0.0.1:5500', 'https://mac-netzwerk.net'], // Erlauben Sie mehrere Origins
    credentials: true
}));

// Redis Client Initialisierung
// Stellen Sie sicher, dass Redis läuft und über REDIS_URL erreichbar ist,
// oder passen Sie die URL entsprechend an.
const redisClient = createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    legacyMode: true // Hinzugefügt für Kompatibilität von connect-redis v6 mit redis v4
});

redisClient.on('error', function (err) {
    console.error('[Redis] Could not connect to Redis:', err);
});

redisClient.on('connect', function () {
    console.log('[Redis] Connected to Redis.');
});

(async () => {
    try {
        await redisClient.connect();
    } catch (err) {
        console.error('[Redis] Client connection error:', err);
    }
})();

// Session-Konfiguration mit RedisStore
app.use(session({
    store: new RedisStore({ client: redisClient, prefix: 'macsess:' }), // Redis als Session-Speicher
    secret: process.env.SESSION_SECRET, // SEHR WICHTIG: In Produktion durch eine sichere Umgebungsvariable ersetzen!
    resave: false,
    saveUninitialized: false, // Empfohlen für Produktion, keine leeren Sessions speichern
    cookie: {
        secure: process.env.NODE_ENV === 'production', // In Produktion true (HTTPS), in Entwicklung false (HTTP)
        httpOnly: true,
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // 'none' erfordert secure: true
        path: '/',
        maxAge: 1000 * 60 * 60 * 24 // 1 Tag Lebensdauer für das Cookie
    }
}));

const client_id = process.env.DISCORD_CLIENT_ID; // Aus Umgebungsvariable laden
const client_secret = process.env.DISCORD_CLIENT_SECRET; // Aus Umgebungsvariable laden

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
        console.log('Vor session.save:', req.session);
        req.session.save(err => {
            if (err) {
                console.error('Session save error:', err);
            } else {
                console.log('Session wurde gespeichert:', req.sessionID);
            }
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