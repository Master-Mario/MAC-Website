require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cors = require('cors'); // CORS-Middleware importieren
const axios = require('axios');
const path = require('path');

const app = express();

// Trust proxy für Produktionsumgebungen hinter Nginx/Apache
app.set('trust proxy', 1);

// Middleware Setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Produktions-Konfiguration
const frontend_url = process.env.WEBSITE_URL || 'https://mac-netzwerk.net';
const discord_redirect_uri = process.env.DISCORD_CALLBACK_URL || 'https://mac-netzwerk.net/login/callback';

// CORS-Konfiguration - erlaube mehrere Origins
app.use(cors({
  origin: ['http://localhost:5500', 'http://127.0.0.1:5500', 'https://mac-netzwerk.net'],
  credentials: true,
  optionsSuccessStatus: 200
}));

// Session-Konfiguration mit Fallback für Redis
let sessionConfig = {
  secret: process.env.SESSION_SECRET || 'BITTE_UNBEDINGT_AENDERN_IN_PRODUKTION',
  resave: true, // Auf true geändert für bessere Kompatibilität
  saveUninitialized: true, // Auf true geändert für bessere Kompatibilität
  name: 'mac.sid', // Spezifischer Name für das Session-Cookie
  cookie: {
    secure: false, // Auf false gesetzt, damit Cookies auch ohne HTTPS funktionieren
    httpOnly: true,
    sameSite: 'lax', // Auf 'lax' gesetzt für bessere Kompatibilität
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 Tage Lebensdauer für das Cookie (erhöht von 1 Tag)
  }
};

// Versuche Redis zu verwenden, falls verfügbar
try {
  const { createClient } = require('redis');
  const RedisStore = require('connect-redis')(session);

  console.log('Versuche Verbindung zu Redis herzustellen...');

  const redisClient = createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    legacyMode: true // Für Kompatibilität mit älteren connect-redis Versionen
  });

  redisClient.on('error', function (err) {
    console.error('[Redis] Verbindungsfehler:', err);
    console.log('[Redis] Fallback auf MemoryStore (nicht für Produktion empfohlen)');
  });

  redisClient.on('connect', function () {
    console.log('[Redis] Verbunden mit Redis-Server.');
  });

  // Asynchrone Verbindung zu Redis herstellen
  (async () => {
    try {
      await redisClient.connect();
      sessionConfig.store = new RedisStore({ client: redisClient, prefix: 'macsess:' });
      console.log('[Redis] Store für Sessions aktiviert');
    } catch (err) {
      console.error('[Redis] Client-Verbindungsfehler:', err);
      console.log('[Redis] Fallback auf MemoryStore');
    }

    // Session-Middleware initialisieren, nachdem Redis-Verbindung versucht wurde
    initializeApp();
  })();
} catch (err) {
  console.log('[Redis] Module nicht verfügbar:', err.message);
  console.log('[Redis] Verwende MemoryStore (nicht für Produktion empfohlen)');

  // Session-Middleware initialisieren ohne Redis
  initializeApp();
}

function initializeApp() {
  // Session-Middleware mit der finalen Konfiguration initialisieren
  app.use(session(sessionConfig));

  // Session-Debugging-Middleware
  app.use((req, res, next) => {
    if (req.session) {
      console.log('Session aktiv:', {
        id: req.sessionID,
        hasUser: !!req.session.user,
        cookie: req.session.cookie
      });
    } else {
      console.log('Keine Session gefunden');
    }
    next();
  });

  // Statische Dateien bereitstellen
  app.use(express.static(path.join(__dirname, '../')));

  setupRoutes();
}

function setupRoutes() {
  const client_id = process.env.DISCORD_CLIENT_ID;
  const client_secret = process.env.DISCORD_CLIENT_SECRET;

  if (!client_id || !client_secret) {
    console.error('WARNUNG: Discord Client ID oder Secret fehlt. Auth wird nicht funktionieren!');
  }

  // Login-Route für Discord OAuth
  app.get('/login', (req, res) => {
    console.log('Login-Anfrage erhalten, leite zu Discord weiter');
    const url = `https://discord.com/api/oauth2/authorize?client_id=${client_id}&redirect_uri=${encodeURIComponent(discord_redirect_uri)}&response_type=code&scope=identify+email`;
    res.redirect(url);
  });

  // Callback-Route für Discord OAuth
  app.get('/login/callback', async (req, res) => {
    console.log('Callback von Discord erhalten');
    const code = req.query.code;
    if (!code) {
      console.error('Kein Code in der Anfrage gefunden');
      return res.redirect(frontend_url + '/?error=nocode');
    }

    const params = new URLSearchParams();
    params.append('client_id', client_id);
    params.append('client_secret', client_secret);
    params.append('grant_type', 'authorization_code');
    params.append('code', code);
    params.append('redirect_uri', discord_redirect_uri);

    try {
      console.log('Fordere Token von Discord an...');
      const tokenRes = await axios.post('https://discord.com/api/oauth2/token', params, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });

      const access_token = tokenRes.data.access_token;
      console.log('Token erhalten, fordere Benutzerinformationen an...');

      const userRes = await axios.get('https://discord.com/api/users/@me', {
        headers: { Authorization: `Bearer ${access_token}` }
      });

      console.log('Benutzerinformationen erhalten:', {
        id: userRes.data.id,
        username: userRes.data.username
      });

      req.session.user = userRes.data;

      // Stelle sicher, dass die Session gespeichert ist, bevor weitergeleitet wird
      req.session.save(err => {
        if (err) {
          console.error('Session-Speicherfehler:', err);
        } else {
          console.log('Session gespeichert:', req.sessionID);
        }
        res.redirect(frontend_url + '/');
      });
    } catch (e) {
      console.error('Login-Callback-Fehler:', e.response ? e.response.data : e.message);
      if (e.response && e.response.data) {
        console.error('Discord API-Fehlerdetails:', e.response.data);
      }

      // Fehlerseite im Frontend mit Parameter für spezifische Fehlermeldung
      const errorQuery = e.response && e.response.data && e.response.data.error_description ?
          `?error=${encodeURIComponent(e.response.data.error_description)}` :
          '?error=unknown';
      res.redirect(frontend_url + '/' + errorQuery);
    }
  });

  // Logout-Route
  app.get('/logout', (req, res) => {
    console.log('Logout-Anfrage erhalten');
    req.session.destroy(err => {
      if (err) {
        console.error('Fehler beim Löschen der Session:', err);
        return res.status(500).send('Fehler beim Abmelden.');
      }
      res.clearCookie('connect.sid'); // Cookie löschen
      res.redirect('/');
    });
  });

  // API-Route für Auth-Status
  app.get('/api/auth/status', (req, res) => {
    console.log('Auth-Status angefragt, Session ID:', req.sessionID);

    // Cache-Header setzen, um Caching zu verhindern
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');

    if (req.session.user) {
      console.log('Benutzer in Session gefunden:', {
        username: req.session.user.username,
        id: req.session.user.id
      });
      res.json({ loggedIn: true, user: req.session.user });
    } else {
      console.log('Kein Benutzer in Session gefunden');
      res.json({ loggedIn: false });
    }
  });

  // Fallback für alle HTML-Anfragen
  app.get('/*.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../', req.path));
  });

  // Fallback-Route für die Startseite
  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../home/index.html'));
  });

  // Fallback-Route für alle anderen Anfragen
  app.use((req, res) => {
    res.sendFile(path.join(__dirname, '../home/index.html'));
  });
}

// Prozess-Beendigung sauber behandeln
process.on('SIGTERM', () => {
  console.log('SIGTERM Signal erhalten, Server wird sauber heruntergefahren');
  process.exit(0);
});

// Server starten
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server läuft auf Port ${PORT}`);
  console.log('Umgebung:', process.env.NODE_ENV || 'development');
  console.log(`Auth-Callback-URL: ${discord_redirect_uri}`);
});
