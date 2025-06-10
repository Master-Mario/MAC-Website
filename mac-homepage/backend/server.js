require('dotenv').config();

const express = require('express');
const session = require('express-session');
const { createClient } = require('redis');
const RedisStore = require('connect-redis')(session);
const cors = require('cors');
const axios = require('axios');
const fetch = require('node-fetch');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();

// Cloudflare KV Konfiguration
const CLOUDFLARE_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const CLOUDFLARE_ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID;
const CLOUDFLARE_KV_NAMESPACE_ID = process.env.CLOUDFLARE_KV_NAMESPACE_ID;

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
    origin: function (origin, callback) {
        // Erlaubte Origins
        const allowedOrigins = [
            'http://localhost:5500',
            'http://127.0.0.1:5500',
            'https://mac-netzwerk.net',
            'https://www.mac-netzwerk.net'
        ];

        // Erlaube Requests ohne Origin (z.B. mobile apps, Postman)
        if (!origin) return callback(null, true);

        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Middleware für Stripe Webhook (benötigt raw body, daher vor express.json())
app.post('/webhook', express.raw({type: 'application/json'}), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error(`Webhook signature verification failed: ${err.message}`);
    return res.sendStatus(400);
  }

  // Handle the event
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const minecraftUsername = session.metadata.minecraft_username;

    if (minecraftUsername) {
      try {
        // 1. Minecraft UUID abrufen
        const mojangResponse = await fetch(`https://api.mojang.com/users/profiles/minecraft/${minecraftUsername}`);
        if (!mojangResponse.ok) {
          throw new Error(`Mojang API error: ${mojangResponse.statusText}`);
        }
        const mojangData = await mojangResponse.json();
        const playerUUID = mojangData.id;

        // 2. Zu Cloudflare KV hinzufügen
        const kvKey = `player:${playerUUID}`;
        const kvValue = JSON.stringify({
          whitelisted: true,
          registered_at: new Date().toISOString(),
          playtime_seconds: 0, // Initialwert
          last_seen: new Date().toISOString() // Initialwert
        });

        const cfResponse = await fetch(`https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/storage/kv/namespaces/${CLOUDFLARE_KV_NAMESPACE_ID}/values/${kvKey}`, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${CLOUDFLARE_API_TOKEN}`,
            'Content-Type': 'application/json'
          },
          body: kvValue
        });

        if (!cfResponse.ok) {
          const errorText = await cfResponse.text();
          throw new Error(`Cloudflare KV API error: ${cfResponse.statusText} - ${errorText}`);
        }
        console.log(`Player ${minecraftUsername} (UUID: ${playerUUID}) successfully added to whitelist.`);

      } catch (error) {
        console.error(`Error processing payment for ${minecraftUsername}:`, error);
        // Hier könntest du eine Benachrichtigung an dich senden, um den Fall manuell zu prüfen
      }
    } else {
      console.error('Minecraft username not found in session metadata.');
    }
  }

  res.json({received: true});
});

// Middleware zum Parsen von JSON-Request-Bodies für andere Routen
// Diese Zeile MUSS NACH dem Stripe Webhook stehen.
app.use(express.json());

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
    store: new RedisStore({ client: redisClient, prefix: 'macsess:' }),
    secret: process.env.SESSION_SECRET || 'BITTE_UNBEDINGT_AENDERN_IN_PRODUKTION',
    resave: false,
    saveUninitialized: false,
    name: 'sessionId', // Expliziter Cookie-Name
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Nur in Produktion auf true
        httpOnly: true,
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        domain: process.env.NODE_ENV === 'production' ? '.mac-netzwerk.net' : undefined,
        path: '/',
        maxAge: 1000 * 60 * 60 * 24 * 30 // 30 Tage (nicht 356)
    }
}));

const client_id = process.env.DISCORD_CLIENT_ID || '1381338008829165658'; // Aus Umgebungsvariable laden
const client_secret = process.env.DISCORD_CLIENT_SECRET || 'l_6FNh5yNmQYcAStNQsJ2AXZ42kZf0Xo'; // Aus Umgebungsvariable laden

app.get('/login', (req, res) => {
    const url = `https://discord.com/api/oauth2/authorize?client_id=${client_id}&redirect_uri=${encodeURIComponent(discord_redirect_uri)}&response_type=code&scope=identify+email`;
    res.redirect(url);
});

app.get('/api/debug/session', (req, res) => {
    console.log('Session ID:', req.sessionID);
    console.log('Session:', req.session);
    console.log('Headers:', req.headers);

    // Überprüfe, ob der Set-Cookie-Header generiert wird
    console.log('Response Headers vor Send:', res.getHeaders());

    res.json({
        sessionID: req.sessionID,
        hasSession: !!req.session,
        hasUser: !!req.session?.user,
        cookies: req.headers.cookie,
        user: req.session?.user || null
    });

    // Logge die Response Headers nach Send
    console.log('Response Headers nach Send:', res.getHeaders());
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
        if (!access_token) {
            throw new Error('Access token not found in response');
        }

        const userRes = await axios.get('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        // Benutzerdaten der Session zuweisen
        req.session.user = userRes.data;

        // Session speichern und Cookies explizit setzen
        console.log('Vor session.save:', req.session);
        req.session.save(err => {
            if (err) {
                console.error('Session save error:', err);
                return res.redirect(frontend_url + '/login-failed.html?error=session_save_failed');
            }

            console.log('Session wurde gespeichert:', req.sessionID);
            console.log('Cookie-Name:', req.sessionID ? 'sessionId' : 'connect.sid');

            // Setze das Cookie manuell
            const cookieName = 'sessionId';
            const cookieValue = req.sessionID;
            const cookieOptions = {
                path: '/',
                maxAge: 1000 * 60 * 60 * 24 * 30, // 30 Tage
                httpOnly: true,
                secure: true,
                sameSite: 'none',
                domain: '.mac-netzwerk.net'
            };

            res.cookie(cookieName, cookieValue, cookieOptions);
            console.log('Cookie manuell gesetzt:', cookieName, cookieValue, cookieOptions);
            console.log('Response Headers nach Cookie-Setzung:', res.getHeaders());

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

    // Zusätzliche Debug-Logs
    console.log('--- Auth Status Check ---');
    console.log('Cookie-Header:', req.headers.cookie);
    console.log('Session ID (req.sessionID):', req.sessionID);
    console.log('Session:', JSON.stringify(req.session, null, 2));

    // Prüfe direkt in Redis nach der Session
    if (req.sessionID) {
        // Der komplette Redis-Key mit Prefix
        const redisKey = `macsess:${req.sessionID}`;
        console.log('Suche in Redis nach Key:', redisKey);

        redisClient.get(redisKey, (err, data) => {
            if (err) {
                console.error('Redis Fehler beim Abrufen der Session:', err);
            } else {
                console.log('Redis-Daten für Session:', data);

                if (data) {
                    try {
                        // Parse Redis-Daten
                        const sessionData = JSON.parse(data);
                        console.log('Geparste Session-Daten:', sessionData);

                        // Wenn user-Daten in Redis vorhanden sind, aber nicht in req.session
                        if (sessionData.user && !req.session.user) {
                            console.log('User-Daten in Redis gefunden, aber nicht in req.session!');
                            // Manuell die user-Daten aus Redis in req.session setzen
                            req.session.user = sessionData.user;

                            console.log('Session wurde manuell aktualisiert mit User:', sessionData.user);
                            return res.json({ loggedIn: true, user: sessionData.user });
                        }
                    } catch (parseError) {
                        console.error('Fehler beim Parsen der Redis-Daten:', parseError);
                    }
                } else {
                    console.log('Keine Session-Daten in Redis gefunden für ID:', req.sessionID);
                }
            }

            // Normale Überprüfung fortsetzen, wenn Redis-Überprüfung nicht zu einem Return geführt hat
            if (req.session && req.session.user) {
                console.log('req.session.user vorhanden:', JSON.stringify(req.session.user, null, 2));
                res.json({ loggedIn: true, user: req.session.user });
            } else {
                console.log('req.session.user NICHT vorhanden.');
                if (!req.session) {
                    console.log('req.session ist undefined oder null.');
                } else {
                    console.log('req.session ist vorhanden, aber ohne .user');
                }
                res.json({ loggedIn: false });
            }
        });
    } else {
        console.log('Keine Session-ID gefunden!');
        res.json({ loggedIn: false });
    }
});

// Korrekter Endpunkt für Stripe Checkout Session Erstellung
app.post('/create-checkout-session', async (req, res) => { // express.json() wird hier implizit durch app.use(express.json()) oben angewendet
    const { minecraftUsername, email } = req.body;

    if (!minecraftUsername || !email) {
        return res.status(400).json({ error: 'Minecraft username and email are required.' });
    }

    const totalServerCost = 10; // Beispiel: 10 EUR
    let numberOfPlayers = 1;

    try {
        const listKeysResponse = await fetch(`https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/storage/kv/namespaces/${CLOUDFLARE_KV_NAMESPACE_ID}/keys?prefix=player:`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${CLOUDFLARE_API_TOKEN}`,
                'Content-Type': 'application/json'
            }
        });

        if (listKeysResponse.ok) {
            const keysData = await listKeysResponse.json();
            if (keysData.success && keysData.result) {
                numberOfPlayers = Math.max(1, keysData.result.length);
            }
        } else {
            console.warn('Could not fetch player keys from Cloudflare KV, using default player count.', await listKeysResponse.text());
        }
    } catch(err) {
        console.warn("Error fetching player count from Cloudflare KV, using default player count.", err);
    }

    const pricePerPlayer = Math.max(1, totalServerCost / numberOfPlayers);

    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card', 'paypal', 'klarna'],
            line_items: [{
                price_data: {
                    currency: 'eur',
                    product_data: {
                        name: 'MAC-SMP Server-Zugang',
                        description: `Monatliche Kostenbeteiligung für MAC-SMP (Minecraft: ${minecraftUsername})`,
                    },
                    unit_amount: Math.round(pricePerPlayer * 100),
                },
                quantity: 1,
            }],
            mode: 'payment',
            success_url: `${frontend_url}/smp.html?payment_success=true&session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${frontend_url}/smp.html?payment_cancelled=true`,
            customer_email: email,
            metadata: {
                minecraft_username: minecraftUsername
            }
        });
        res.json({ id: session.id });
    } catch (error) {
        console.error("Error creating Stripe session:", error);
        res.status(500).json({ error: 'Failed to create payment session.' });
    }
});

app.get('/profile', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    res.send(`Hallo ${req.session.user.username}!`);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server läuft auf Port ${PORT}`));