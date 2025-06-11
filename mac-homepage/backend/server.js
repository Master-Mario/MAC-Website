// Umgebungsvariablen laden
require('dotenv').config();

// Abhängigkeiten importieren
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const path = require('path');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const axios = require('axios');

// Hilfsbibliothek für einen einfachen In-Memory-Store (für Produktionsumgebungen sollte ein persistenter Store wie Redis verwendet werden)
// Hinweis: Für die Produktion sollte Cloudflare KV hier eingebunden werden
const UserStore = {
    users: {},

    findById: function(id) {
        return this.users[id] || null;
    },

    saveUser: function(user) {
        this.users[user.id] = user;
        return user;
    },

    removeUser: function(id) {
        if (this.users[id]) {
            delete this.users[id];
            return true;
        }
        return false;
    }
};

// Server und Middleware konfigurieren
const app = express();

// CORS konfigurieren
app.use(cors({
    origin: process.env.WEBSITE_URL,
    credentials: true
}));

// Body Parser und Cookie Parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session konfigurieren
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.COOKIE_SECURE === 'true', // Sollte in Produktion true sein
        maxAge: 1000 * 60 * 60 * 24 * 7 // 7 Tage
    }
}));

// Passport initialisieren
app.use(passport.initialize());
app.use(passport.session());

// Discord-Strategie konfigurieren
const discordScopes = ['identify', 'email'];

passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: process.env.DISCORD_CALLBACK_URL,
    scope: discordScopes
}, async (accessToken, refreshToken, profile, done) => {
    try {
        // User zum Store hinzufügen oder aktualisieren
        const user = {
            id: profile.id,
            username: profile.username,
            discriminator: profile.discriminator,
            avatar: profile.avatar,
            email: profile.email,
            accessToken,
            refreshToken,
            lastLogin: new Date()
        };

        UserStore.saveUser(user);
        return done(null, user);
    } catch (error) {
        return done(error, null);
    }
}));

// Passport-Serialisierung
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    const user = UserStore.findById(id);
    done(null, user);
});

// Statische Dateien aus dem home-Verzeichnis bereitstellen
app.use(express.static(path.join(__dirname, '../home')));

// Middleware für Authentifizierungsprüfung
const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
};

// Auth-Routen
app.get('/login', passport.authenticate('discord', { scope: discordScopes }));

app.get('/login/callback',
    passport.authenticate('discord', {
        failureRedirect: '/?auth_error=true'
    }),
    (req, res) => {
        // Erfolgreiche Authentifizierung
        res.redirect('/');
    }
);

app.get('/logout', (req, res) => {
    req.logout(function(err) {
        if (err) {
            console.error('Fehler beim Logout:', err);
            return res.status(500).json({ error: 'Logout fehlgeschlagen' });
        }
        res.redirect('/');
    });
});

// API-Routen
app.get('/api/auth/status', (req, res) => {
    if (req.isAuthenticated()) {
        const userData = {
            id: req.user.id,
            username: req.user.username,
            avatar: req.user.avatar,
            email: req.user.email
        };

        return res.json({
            loggedIn: true,
            user: userData
        });
    }

    res.json({
        loggedIn: false,
        user: null
    });
});

// Alle anderen Routen zur index.html weiterleiten für clientseitiges Routing
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../home/index.html'));
});

// Server starten
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server läuft auf Port ${PORT}`);
    console.log(`Discord Callback URL: ${process.env.DISCORD_CALLBACK_URL}`);
    console.log(`Umgebung: ${process.env.NODE_ENV}`);
});

// Hinweis für die Integration von Cloudflare KV in der Produktion:
/*
Für die Produktionsumgebung sollte der UserStore durch eine persistente Lösung wie Cloudflare KV ersetzt werden.
Hier ein Beispiel für die Integration:

1. Importiere die KV-Bibliothek:
const { getAssetFromKV } = require('@cloudflare/kv-asset-handler');

2. Erstelle eine Klasse für den UserStore mit KV:
class CloudflareKVUserStore {
    constructor(KV_NAMESPACE) {
        this.kv = KV_NAMESPACE;
    }

    async findById(id) {
        try {
            return await this.kv.get(`user:${id}`, 'json');
        } catch (error) {
            console.error('KV Fehler beim Abrufen des Benutzers:', error);
            return null;
        }
    }

    async saveUser(user) {
        try {
            await this.kv.put(`user:${user.id}`, JSON.stringify(user));
            return user;
        } catch (error) {
            console.error('KV Fehler beim Speichern des Benutzers:', error);
            throw error;
        }
    }

    async removeUser(id) {
        try {
            await this.kv.delete(`user:${id}`);
            return true;
        } catch (error) {
            console.error('KV Fehler beim Löschen des Benutzers:', error);
            return false;
        }
    }
}

3. Instanziiere und verwende den Store:
const userStore = new CloudflareKVUserStore(KV_NAMESPACE);

4. Passe die Passport-Funktionen entsprechend an (mit async/await):
passport.deserializeUser(async (id, done) => {
    try {
        const user = await userStore.findById(id);
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});
*/
