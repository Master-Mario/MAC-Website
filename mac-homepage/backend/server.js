const express = require('express');
const session = require('express-session');
const { createClient } = require('redis');
const RedisStore = require('connect-redis')(session); // angepasst für ältere connect-redis Versionen
const cors = require('cors'); // CORS-Middleware importieren
const axios = require('axios');
const fetch = require('node-fetch'); // Hinzugefügt für Cloudflare API
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY); // Stripe-Initialisierung

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
    origin: ['http://localhost:5500', 'http://127.0.0.1:5500', 'https://mac-netzwerk.net'], // Erlauben Sie mehrere Origins
    credentials: true
}));

// Middleware für Stripe Webhook (muss vor app.use(express.json()) stehen, wenn dieses global genutzt wird)
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

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || 'sk_test_...'); // Stripe Secret Key

app.post('/create-checkout-session', async (req, res) => {
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [
                {
                    price_data: {
                        currency: 'eur',
                        product_data: {
                            name: 'MAC-SMP Server Zugang',
                            description: 'Monatliche Kostenbeteiligung für den MAC-SMP Server.',
                        },
                        unit_amount: 200, // Betrag in Cent (z.B. 2€)
                    },
                    quantity: 1,
                },
            ],
            mode: 'subscription',
            success_url: `${frontend_url}/success.html?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${frontend_url}/cancel.html`,
        });

        res.json({ id: session.id });
    } catch (error) {
        console.error('Error creating checkout session:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Session-Konfiguration mit RedisStore
app.use(session({
    store: new RedisStore({ client: redisClient, prefix: 'macsess:' }), // Redis als Session-Speicher
    secret: process.env.SESSION_SECRET || 'BITTE_UNBEDINGT_AENDERN_IN_PRODUKTION', // SEHR WICHTIG: In Produktion durch eine sichere Umgebungsvariable ersetzen!
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

// Neuer Endpunkt für Stripe Checkout Session Erstellung
app.post('/create-checkout-session', express.json(), async (req, res) => {
    const { minecraftUsername, email } = req.body;

    if (!minecraftUsername || !email) {
        return res.status(400).json({ error: 'Minecraft username and email are required.' });
    }

    const totalServerCost = 10; // Beispiel: 10 EUR
    let numberOfPlayers = 1; // Standardwert, falls KV-Abruf fehlschlägt oder keine Spieler vorhanden sind

    try {
        // Anzahl der Spieler aus Cloudflare KV abrufen
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
                numberOfPlayers = Math.max(1, keysData.result.length); // Mindestens 1 Spieler annehmen, um Division durch Null zu vermeiden
            }
        } else {
            console.warn('Could not fetch player keys from Cloudflare KV, using default player count.', await listKeysResponse.text());
        }
    } catch(err) {
        console.warn("Error fetching player count from Cloudflare KV, using default player count.", err);
    }

    // Wenn numberOfPlayers nach dem KV-Abruf immer noch 0 ist (oder weniger, was nicht passieren sollte mit Math.max(1, ...)),
    // und wir wollen, dass der erste Spieler die vollen Kosten trägt, oder einen Mindestpreis ansetzen.
    // Für dieses Beispiel: Wenn es 0 Spieler gäbe, würde der neue Spieler die Kosten für 1 Spieler zahlen.
    // Wenn bereits Spieler da sind, werden die Kosten geteilt.
    // Die Logik Math.max(1, keysData.result.length) stellt sicher, dass numberOfPlayers mindestens 1 ist, wenn die Abfrage erfolgreich war.
    // Wenn die Abfrage fehlschlägt, bleibt der numberOfPlayers auf dem initialen Wert von 1.

    const pricePerPlayer = Math.max(1, totalServerCost / numberOfPlayers); // Mindestens 1 EUR pro Spieler

    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card', 'paypal', 'klarna'], // Füge hier weitere Zahlungsmethoden hinzu
            line_items: [{
                price_data: {
                    currency: 'eur',
                    product_data: {
                        name: 'MAC-SMP Server-Zugang',
                        description: `Monatliche Kostenbeteiligung für MAC-SMP (Minecraft: ${minecraftUsername})`,
                    },
                    unit_amount: Math.round(pricePerPlayer * 100), // Betrag in Cent
                },
                quantity: 1,
            }],
            mode: 'payment', // Für einmalige Zahlungen; für Abos 'subscription'
            success_url: `${frontend_url}/smp.html?payment_success=true&session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${frontend_url}/smp.html?payment_cancelled=true`,
            customer_email: email, // E-Mail des Kunden für die Quittung und um Gast-Checkouts zu ermöglichen
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