require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const path = require('path');
const cookieParser = require('cookie-parser');
const cors = require('cors');

// Initialisiere Express App
const app = express();
const PORT = process.env.PORT || 3000;

// Prüfe, ob alle erforderlichen Umgebungsvariablen vorhanden sind
const requiredEnvVars = ['DISCORD_CLIENT_ID', 'DISCORD_CLIENT_SECRET', 'DISCORD_CALLBACK_URL', 'SESSION_SECRET'];
const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
  console.error(`Fehlende Umgebungsvariablen: ${missingVars.join(', ')}`);
  process.exit(1);
}

// CORS konfigurieren - nur die eigene Domain erlauben
const corsOptions = {
  origin: process.env.WEBSITE_URL || 'https://mac-netzwerk.net',
  credentials: true,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Middleware Setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session-Konfiguration mit MemoryStore
// Hinweis: In Produktion sollte ein persistenter Store verwendet werden
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Nur HTTPS im Produktionsmodus
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000, // Session läuft nach 7 Tagen ab
    sameSite: 'lax' // Erlaube Cookies für Cross-Site-Requests
  }
}));

// Session-Debugging-Middleware
app.use((req, res, next) => {
  // Protokolliere Session-Informationen bei jeder Anfrage
  if (req.session) {
    console.log('Session aktiv:', {
      id: req.sessionID,
      hasUser: !!req.session.passport?.user,
      cookie: req.session.cookie
    });
  } else {
    console.log('Keine Session gefunden');
  }
  next();
});

// Passport initialisieren
app.use(passport.initialize());
app.use(passport.session());

// Passport-Strategie für Discord konfigurieren
passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: process.env.DISCORD_CALLBACK_URL,
  scope: ['identify', 'email']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Hier speichern wir nur das Discord-Profil direkt in der Session
    // Wir verwenden keine Datenbank, da es nicht explizit gefordert wurde
    return done(null, profile);
  } catch (error) {
    return done(error, null);
  }
}));

// Serialisieren und Deserialisieren des Benutzers für die Session
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Statische Dateien bereitstellen
app.use(express.static(path.join(__dirname, '../')));

// Auth-Routen
// Weiterleitung zur Discord-Authentifizierung
app.get('/login', passport.authenticate('discord'));

// Discord-Callback-Route
app.get('/login/callback',
  passport.authenticate('discord', {
    failureRedirect: '/'
  }),
  (req, res) => {
    // Erfolgreiche Authentifizierung, Weiterleitung zur Startseite
    res.redirect('/');
  }
);

// Logout-Route
app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error('Fehler beim Logout:', err);
      return res.status(500).send('Fehler beim Abmelden');
    }
    res.redirect('/');
  });
});

// API-Routen
// Status-Endpunkt zum Überprüfen des Auth-Status
app.get('/api/auth/status', (req, res) => {
  console.log('Auth-Status angefragt:');
  console.log('isAuthenticated:', req.isAuthenticated());
  console.log('Session-ID:', req.sessionID);
  console.log('User in Session:', req.user);

  if (req.isAuthenticated()) {
    // Filtere sensible Informationen heraus und sende nur das Nötigste
    const { id, username, discriminator, avatar, email } = req.user;
    console.log('Sende Benutzerinfo zurück:', { id, username });
    return res.json({
      loggedIn: true,
      user: { id, username, discriminator, avatar, email }
    });
  }

  console.log('Benutzer ist nicht authentifiziert');
  return res.json({ loggedIn: false });
});

// Fallback für alle HTML-Anfragen mit exakter Übereinstimmung
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

// Prozess-Beendigung sauber behandeln
process.on('SIGTERM', () => {
  console.log('SIGTERM Signal erhalten, Server wird sauber heruntergefahren');
  process.exit(0);
});

// Server starten
app.listen(PORT, () => {
  console.log(`Server läuft auf Port ${PORT}`);
  console.log('Umgebung:', process.env.NODE_ENV || 'development');
  console.log(`Auth-Callback-URL: ${process.env.DISCORD_CALLBACK_URL}`);
});
