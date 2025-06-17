// Globale Hilfsfunktionen für Tabellen-Setup
async function ensurePaymentSetupsTable(env) {
    const check = await env.DB.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='payment_setups';"
    ).first();
    if (!check) {
        await env.DB.prepare(`
            CREATE TABLE payment_setups (
                minecraft_uuid TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                stripe_id TEXT NOT NULL,
                payment_authorized BOOLEAN NOT NULL DEFAULT false,
                payment_method TEXT NOT NULL DEFAULT 'unknown',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                canceled_at TEXT DEFAULT NULL,
                used_seconds_this_month INTEGER NOT NULL DEFAULT 0
            );
        `).run();
    } else {
        const columns = await env.DB.prepare("PRAGMA table_info(payment_setups);").all();
        const colArray = columns.results || columns;
        if (!colArray.some(col => col.name === 'created_at')) {
            await env.DB.prepare("ALTER TABLE payment_setups ADD COLUMN created_at TEXT;").run();
            await env.DB.prepare("UPDATE payment_setups SET created_at = ? WHERE created_at IS NULL;").bind(new Date().toISOString()).run();
        }
        if (!colArray.some(col => col.name === 'canceled_at')) {
            await env.DB.prepare("ALTER TABLE payment_setups ADD COLUMN canceled_at TEXT;").run();
        }
        if (!colArray.some(col => col.name === 'used_seconds_this_month')) {
            await env.DB.prepare("ALTER TABLE payment_setups ADD COLUMN used_seconds_this_month INTEGER NOT NULL DEFAULT 0;").run();
        }
    }
}

async function ensureBillingHistoryTable(env) {
    await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS billing_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            abrechnungsmonat TEXT NOT NULL,
            nutzungszeit INTEGER NOT NULL,
            kostenanteil REAL NOT NULL,
            timestamp TEXT NOT NULL
        );
    `).run();
}

export default {
    async fetch(request, env, ctx) {
        const jwtSecret = new TextEncoder().encode(env.JWT_SECRET);

        // Neue Definition von signJWT
        async function signJWT(payload, ttlSeconds = 604800) {
            const header = { alg: 'HS256', typ: 'JWT' };
            const now = Math.floor(Date.now() / 1000);
            payload.iat = now;
            payload.exp = now + ttlSeconds;
        
            const base64url = (obj) => btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
            const toSign = `${base64url(header)}.${base64url(payload)}`;
        
            const signature = await crypto.subtle.sign(
                { name: 'HMAC' },
                await crypto.subtle.importKey('raw', jwtSecret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']),
                new TextEncoder().encode(toSign)
            );
        
            const sigB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
                .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
            return `${toSign}.${sigB64}`;
        }
        
        // Neue Definition von verifyJWT
        async function verifyJWT(token) {
            try {
                const [headerB64, payloadB64, sigB64] = token.split('.');
                const encoder = new TextEncoder();
                const key = await crypto.subtle.importKey('raw', jwtSecret, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
                const data = encoder.encode(`${headerB64}.${payloadB64}`);
                const sig = Uint8Array.from(atob(sigB64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
                const valid = await crypto.subtle.verify('HMAC', key, sig, data);
                if (!valid) return null;
                return JSON.parse(atob(payloadB64));
            } catch (_) {
                return null;
            }
        }

        function getCookie(request, name) {
            const cookies = Object.fromEntries(
                (request.headers.get('Cookie') || '')
                    .split(';')
                    .map(c => c.trim().split('=').map(decodeURIComponent))
            );
            return cookies[name];
        }

        function setJWTCookie(jwt) {
            return `mac_sid=${jwt}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax; Secure`;
        }

        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;
        
        const token = getCookie(request, 'mac_sid');
        const session = token ? await verifyJWT(token) : null;

        const headers = new Headers();

        // /login
        if (path === '/login') {
            const params = new URLSearchParams({
                client_id: env.DISCORD_CLIENT_ID,
                redirect_uri: env.DISCORD_CALLBACK_URL,
                response_type: 'code',
                scope: 'identify email'
            });
            return Response.redirect(`https://discord.com/api/oauth2/authorize?${params}`, 302);
        }

        // /login/callback
        if (path === '/login/callback') {
            const code = url.searchParams.get('code');
            if (!code) return Response.redirect(env.WEBSITE_URL + '/?error=no_code', 302);

            try {
                const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: new URLSearchParams({
                        client_id: env.DISCORD_CLIENT_ID,
                        client_secret: env.DISCORD_CLIENT_SECRET,
                        grant_type: 'authorization_code',
                        code,
                        redirect_uri: env.DISCORD_CALLBACK_URL
                    })
                });
                const { access_token } = await tokenRes.json();

                const userRes = await fetch('https://discord.com/api/users/@me', {
                    headers: { Authorization: `Bearer ${access_token}` }
                });
                const user = await userRes.json();

                const jwt = await signJWT({ user });
                headers.set('Set-Cookie', setJWTCookie(jwt));
                headers.set('Location', env.WEBSITE_URL);
                return new Response(null, { status: 302, headers });
            } catch (err) {
                return Response.redirect(env.WEBSITE_URL + '/?error=login_failed', 302);
            }
        }

        // /logout
        if (path === '/logout') {
            headers.set('Set-Cookie', 'mac_sid=; Path=/; Max-Age=0;');
            headers.set('Location', '/');
            return new Response(null, { status: 302, headers });
        }

        // /api/auth/status
        if (path === '/api/auth/status') {
            headers.set('Content-Type', 'application/json');
            headers.set('Cache-Control', 'no-store');
            return new Response(JSON.stringify({
                loggedIn: !!session?.user,
                user: session?.user || null
            }), { headers });
        }

        if (path === '/create-checkout-session' && method === 'POST') {
            await ensurePaymentSetupsTable(env);
            const body = await request.json();
            const { email, minecraftUsername } = body;
            if (!email || !minecraftUsername) {
                return new Response(JSON.stringify({ error: 'Daten erforderlich' }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            // PlayerDB API: Username -> UUID
            let minecraftUuid;
            try {
                const playerdbRes = await fetch(`https://playerdb.co/api/player/minecraft/${encodeURIComponent(minecraftUsername)}`);
                if (!playerdbRes.ok) throw new Error("PlayerDB API Fehler");
                const playerdbData = await playerdbRes.json();
                minecraftUuid = playerdbData?.data?.player?.id;
                if (!minecraftUuid) throw new Error("UUID nicht gefunden");
            } catch (err) {
                return new Response(JSON.stringify({ error: 'Ungültiger Minecraft Username oder PlayerDB API Fehler' }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            try {
                // Verwende den offiziellen Stripe HTTP API Aufruf
                const stripeUrl = 'https://api.stripe.com/v1/checkout/sessions';
                const formData = new URLSearchParams();
                formData.append('mode', 'setup');
                formData.append('customer_email', email);
                formData.append('success_url', `${env.WEBSITE_URL}/payment-setup-success?session_id={CHECKOUT_SESSION_ID}`);
                formData.append('cancel_url', `${env.WEBSITE_URL}/payment-setup-cancel`);
                formData.append('payment_method_types[]', 'card');
                formData.append('payment_method_types[]', 'sepa_debit');
                formData.append('customer_creation', 'always'); // Erzwinge Customer-Erstellung

                const stripeRes = await fetch(stripeUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`
                    },
                    body: formData.toString()
                });
                const session = await stripeRes.json();
                if (!stripeRes.ok) throw new Error(session.error ? session.error.message : 'Stripe API Fehler');

                // D1 Database Integration: Speichere Minecraft UUID, Email, Stripe Session ID, Zahlungserlaubnis und Methode
                try {
                    // Prüfe, ob es einen bestehenden Eintrag mit dieser UUID oder E-Mail gibt
                    const existing = await env.DB.prepare("SELECT * FROM payment_setups WHERE minecraft_uuid = ? OR email = ?").bind(minecraftUuid, email).first();
                    if (existing) {
                        // Wenn gekündigt, reaktiviere bestehenden Eintrag (statt INSERT)
                        if (existing.canceled_at) {
                            await env.DB.prepare("UPDATE payment_setups SET payment_authorized = 0, stripe_id = ?, payment_method = ?, created_at = ?, canceled_at = NULL WHERE minecraft_uuid = ? OR email = ?")
                                .bind(session.id, "unknown", new Date().toISOString(), minecraftUuid, email)
                                .run();
                        } else {
                            return new Response(JSON.stringify({ error: 'Du bist bereits registriert. Bitte verwende deinen bestehenden Account.' }), {
                                status: 400,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        }
                    } else {
                        // Kein bestehender Eintrag: normal anlegen
                        await env.DB.prepare(
                            "INSERT INTO payment_setups (minecraft_uuid, email, stripe_id, payment_authorized, payment_method, created_at, canceled_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
                        )
                            .bind(minecraftUuid, email, session.id, false, "unknown", new Date().toISOString(), null)
                            .run();
                    }
                    return new Response(JSON.stringify({ url: session.url }), {
                        headers: { 'Content-Type': 'application/json' }
                    });
                } catch (err) {
                    return new Response(JSON.stringify({ error: 'Datenbankfehler: ' + err.message }), {
                        status: 500,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
            } catch (error) {
                return new Response(JSON.stringify({ error: error.message }), {
                    status: 500,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        }

        if (path === '/payment-setup-success') {
            await ensurePaymentSetupsTable(env);
            const sessionId = url.searchParams.get('session_id');
            if (!sessionId) {
                return new Response(JSON.stringify({ error: 'Session ID fehlt' }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            // Stripe-Session abfragen, um Customer-ID zu bekommen
            let customerId = null;
            let session = null;
            try {
                const stripeRes = await fetch(`https://api.stripe.com/v1/checkout/sessions/${sessionId}`, {
                    headers: {
                        'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`
                    }
                });
                session = await stripeRes.json();
                console.log('Stripe-Session:', session); // Logging hinzugefügt
                if (!stripeRes.ok) throw new Error(session.error ? session.error.message : 'Stripe API Fehler');
                customerId = session.customer;
                // Wenn keine Customer-ID, versuche sie aus dem SetupIntent zu holen
                if (!customerId && session.setup_intent) {
                    // SetupIntent abfragen
                    const siRes = await fetch(`https://api.stripe.com/v1/setup_intents/${session.setup_intent}`, {
                        headers: {
                            'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`
                        }
                    });
                    const si = await siRes.json();
                    console.log('Stripe-SetupIntent:', si); // Logging hinzugefügt
                    if (si && si.customer) {
                        customerId = si.customer;
                    }
                }
            } catch (err) {
                return new Response(JSON.stringify({ error: 'Stripe API Fehler: ' + err.message }), {
                    status: 500,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            if (!customerId) {
                return new Response(JSON.stringify({ error: 'Keine Customer-ID in Stripe-Session oder SetupIntent gefunden.' }), {
                    status: 500,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // Update payment_authorized, payment_method und stripe_id (jetzt Customer-ID!) in der Datenbank
            try {
                // Versuche zuerst nach Session-ID zu updaten
                let result = await env.DB.prepare(
                    "UPDATE payment_setups SET payment_authorized = ?, payment_method = ?, stripe_id = ? WHERE stripe_id = ?"
                )
                    .bind(true, "stripe", customerId, sessionId)
                    .run();
                // Falls kein Eintrag aktualisiert wurde, versuche nach E-Mail zu updaten (z.B. nach Datenbankbereinigung)
                if (result.changes === 0) {
                    // Hole E-Mail aus Stripe-Session
                    const email = session.customer_email || session.email;
                    if (email) {
                        await env.DB.prepare(
                            "UPDATE payment_setups SET payment_authorized = ?, payment_method = ?, stripe_id = ? WHERE email = ?"
                        )
                        .bind(true, "stripe", customerId, email)
                        .run();
                    }
                }
            } catch (err) {
                return new Response(JSON.stringify({ error: 'Datenbankfehler: ' + err.message }), {
                    status: 500,
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            // Weiterleitung mit session_id als Query-Parameter
            return new Response(null, {
                status: 303,
                headers: { 'Location': env.WEBSITE_URL + '/payment_success?session_id=' + encodeURIComponent(sessionId) }
            });
        }
        // --- Stripe Session Information Endpoint für Frontend ---
        if (path === '/api/stripe/session' && method === 'GET') {
            const sessionId = url.searchParams.get('session_id');
            if (!sessionId) {
                return new Response(JSON.stringify({ error: 'Session ID fehlt' }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // Stripe Session abfragen
            try {
                const stripeRes = await fetch(`https://api.stripe.com/v1/checkout/sessions/${sessionId}`, {
                    headers: {
                        'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`
                    }
                });
                const session = await stripeRes.json();
                if (!stripeRes.ok) throw new Error(session.error ? session.error.message : 'Stripe API Fehler');
                return new Response(JSON.stringify(session), {
                    headers: { 'Content-Type': 'application/json' }
                });
            } catch (err) {
                return new Response(JSON.stringify({ error: 'Stripe API Fehler: ' + err.message }), {
                    status: 500,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        }
        // --- D1-API: Minecraft-Username anhand der Stripe-Session-ID ausgeben ---
        if (path === '/api/d1/minecraft-username' && method === 'GET') {
            const sessionId = url.searchParams.get('session_id');
            if (!sessionId) {
                return new Response(JSON.stringify({ error: 'Session ID fehlt' }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            await ensurePaymentSetupsTable(env);
            // Suche nach passendem Eintrag in D1
            const row = await env.DB.prepare(
                'SELECT minecraft_uuid FROM payment_setups WHERE stripe_id = ?'
            ).bind(sessionId).first();
            if (!row || !row.minecraft_uuid) {
                return new Response(JSON.stringify({ error: 'Kein Eintrag gefunden' }), {
                    status: 404,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // Hole Username von PlayerDB API
            let minecraftUsername = row.minecraft_uuid;
            try {
                const playerdbRes = await fetch(`https://playerdb.co/api/player/minecraft/${minecraftUsername}`);
                if (playerdbRes.ok) {
                    const playerdbData = await playerdbRes.json();
                    if (playerdbData && playerdbData.data && playerdbData.data.player && playerdbData.data.player.username) {
                        minecraftUsername = playerdbData.data.player.username;
                    }
                }
            } catch (err) {
                // Fallback: UUID anzeigen
            }
            return new Response(JSON.stringify({ minecraftUsername }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }
        // --- D1-API: Abo-Status anhand Discord-User (E-Mail) ausgeben ---
        if (path === '/api/d1/abo-status' && method === 'GET') {
            await ensurePaymentSetupsTable(env);
            if (!session?.user?.email) {
                return new Response(JSON.stringify({ error: 'Nicht eingeloggt oder keine E-Mail im Discord-Account' }), {
                    status: 401,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // Hole Abrechnungsstichtag und Serverkosten aus ENV
            const abrechnungstag = parseInt(env.BILLING_DAY || '1', 10);
            const serverCosts = parseFloat(env.SERVER_COSTS || '0');
            const now = new Date();
            const abrechnungsmonat = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
            const abrechnungsdatum = new Date(now.getFullYear(), now.getMonth(), abrechnungstag, 0, 0, 0, 0);
            // Suche nach passendem Eintrag in D1 über die E-Mail
            const row = await env.DB.prepare(
                'SELECT * FROM payment_setups WHERE email = ?'
            ).bind(session.user.email).first();
            if (!row) {
                return new Response(JSON.stringify({ active: false }), {
                    status: 200,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // Hole Minecraft-Username von PlayerDB API
            let minecraftUsername = row.minecraft_uuid;
            try {
                const playerdbRes = await fetch(`https://playerdb.co/api/player/minecraft/${minecraftUsername}`);
                if (playerdbRes.ok) {
                    const playerdbData = await playerdbRes.json();
                    if (playerdbData && playerdbData.data && playerdbData.data.player && playerdbData.data.player.username) {
                        minecraftUsername = playerdbData.data.player.username;
                    }
                }
            } catch (err) {
                // Fallback: UUID anzeigen
            }
            // Nächster Zahltag berechnen
            let nextPay = null;
            if (!row.canceled_at) {
                // Wenn noch nicht gekündigt, nächster Zahltag ist der nächste Abrechnungstag
                let next = new Date(abrechnungsdatum);
                if (now >= abrechnungsdatum) {
                    next.setMonth(next.getMonth() + 1);
                }
                nextPay = next.toISOString();
            }
            // Anteil berechnen wie in runMonthlyBilling
            let amount = null;
            try {
                // Hole alle Nutzer (auch gekündigte)
                const rows = (await env.DB.prepare('SELECT * FROM payment_setups').all()).results || [];
                let nutzerDaten = [];
                let summeNutzungszeit = 0;
                for (const r of rows) {
                    let nutzungszeit = r.used_seconds_this_month || 0;
                    let createdAt = r.created_at ? new Date(r.created_at) : null;
                    let canceledAt = r.canceled_at ? new Date(r.canceled_at) : null;
                    // Wenn Nutzer im aktuellen Monat registriert wurde und nicht gekündigt hat
                    if (createdAt && createdAt > abrechnungsdatum && !canceledAt) {
                        nutzungszeit += Math.floor((now - createdAt) / 1000);
                    }
                    // Wenn Nutzer im aktuellen Monat gekündigt hat
                    if (createdAt && canceledAt && canceledAt > abrechnungsdatum) {
                        nutzungszeit += Math.floor((canceledAt - createdAt) / 1000);
                    }
                    // Wenn Nutzer schon vor dem Abrechnungsmonat registriert war und nicht gekündigt hat
                    if (createdAt && createdAt <= abrechnungsdatum && !canceledAt) {
                        nutzungszeit += Math.floor((now - abrechnungsdatum) / 1000);
                    }
                    // Wenn Nutzer schon vor dem Abrechnungsmonat registriert war und im aktuellen Monat gekündigt hat
                    if (createdAt && canceledAt && createdAt <= abrechnungsdatum && canceledAt > abrechnungsdatum) {
                        nutzungszeit += Math.floor((canceledAt - abrechnungsdatum) / 1000);
                    }
                    // Wenn Nutzer im Vormonat gekündigt hat, keine Abrechnung mehr
                    if (canceledAt && canceledAt <= abrechnungsdatum) {
                        nutzungszeit = 0;
                    }
                    nutzerDaten.push({
                        email: r.email,
                        nutzungszeit,
                        r
                    });
                    summeNutzungszeit += nutzungszeit;
                }
                // Anteil für aktuellen Nutzer
                const meinNutzer = nutzerDaten.find(n => n.email === row.email);
                if (meinNutzer && meinNutzer.nutzungszeit > 0 && summeNutzungszeit > 0) {
                    amount = (meinNutzer.nutzungszeit / summeNutzungszeit) * serverCosts;
                }
            } catch (err) {
                amount = null;
            }
            // Beispielhafte Felder für die Anzeige
            return new Response(JSON.stringify({
                active: !!row.payment_authorized,
                minecraft_username: minecraftUsername,
                email: row.email,
                stripe_id: row.stripe_id,
                method: row.payment_method,
                since: row.created_at || null, // Registrierungsdatum
                canceled_at: row.canceled_at || null, // Kündigungsdatum
                next_pay: nextPay, // Nächster Zahltag
                amount: amount // Anteil
            }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }
        // --- D1-API: Abo kündigen ---
        if (path === '/api/d1/abo-kuendigen' && method === 'POST') {
            await ensurePaymentSetupsTable(env);
            if (!session?.user?.email) {
                return new Response(JSON.stringify({ error: 'Nicht eingeloggt oder keine E-Mail im Discord-Account' }), {
                    status: 401,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // Robuste Berechnung der im aktuellen Monat genutzten Sekunden
            try {
                // Hole aktuellen Eintrag
                const row = await env.DB.prepare('SELECT created_at, used_seconds_this_month FROM payment_setups WHERE email = ?').bind(session.user.email).first();
                let usedSeconds = 0;
                let createdAt = row?.created_at ? new Date(row.created_at) : null;
                let now = new Date();
                let lastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1);
                let monthStart = new Date(now.getFullYear(), now.getMonth(), 1, 0, 0, 0, 0);
                // Fallback falls Wert nicht gesetzt
                if (typeof row?.used_seconds_this_month === 'number') {
                    usedSeconds = row.used_seconds_this_month;
                }
                // Wenn created_at im aktuellen Monat liegt, zähle Zeit seit created_at
                if (createdAt && createdAt >= monthStart) {
                    usedSeconds += Math.floor((now - createdAt) / 1000);
                } else {
                    // Wenn created_at vor Monatsanfang liegt, zähle nur Zeit seit Monatsanfang
                    // (Abo war schon vorher aktiv, aber nur aktuelle Monatszeit zählt)
                    usedSeconds = Math.floor((now - monthStart) / 1000);
                }
                await env.DB.prepare(
                    'UPDATE payment_setups SET canceled_at = ?, used_seconds_this_month = ? WHERE email = ?'
                ).bind(now.toISOString(), usedSeconds, session.user.email).run();
            } catch (err) {
                return new Response(JSON.stringify({ error: 'Datenbankfehler: ' + err.message }), {
                    status: 500,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            return new Response(JSON.stringify({ success: true }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }
        // Debug-/Test-Endpunkt: Manuelle Abrechnung auslösen
        if (path === '/api/d1/abrechnung-test' && method === 'POST') {
            try {
                await this.runMonthlyBilling(env);
                return new Response(JSON.stringify({ success: true }), {
                    headers: { 'Content-Type': 'application/json' }
                });
            } catch (err) {
                return new Response(JSON.stringify({ error: err.message }), {
                    status: 500,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        }
        // Fallback für nicht erkannte Routen mit 404 Weiterleitung
        return new Response(null, {
            status: 404,
            headers: { 'Location': env.WEBSITE_URL + '/error-pages/404.html', ...headers }
        });
    },
    // Führt die monatliche Abrechnung durch
    async runMonthlyBilling(env) {
        await ensurePaymentSetupsTable(env);
        await ensureBillingHistoryTable(env);
        const now = new Date();
        const abrechnungsmonat = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
        const abrechnungstag = parseInt(env.BILLING_DAY || '1', 10);
        const serverCosts = parseFloat(env.SERVER_COSTS || '0');
        const abrechnungsdatum = new Date(now.getFullYear(), now.getMonth(), abrechnungstag, 0, 0, 0, 0);
        // Hole alle Nutzer (auch gekündigte)
        const rows = (await env.DB.prepare('SELECT * FROM payment_setups').all()).results || [];
        // Berechne Nutzungszeit für alle Nutzer
        let nutzerDaten = [];
        let summeNutzungszeit = 0;
        for (const row of rows) {
            let nutzungszeit = row.used_seconds_this_month || 0;
            let createdAt = row.created_at ? new Date(row.created_at) : null;
            let canceledAt = row.canceled_at ? new Date(row.canceled_at) : null;
            // Wenn Nutzer im aktuellen Monat registriert wurde und nicht gekündigt hat
            if (createdAt && createdAt > abrechnungsdatum && !canceledAt) {
                nutzungszeit += Math.floor((now - createdAt) / 1000);
            }
            // Wenn Nutzer im aktuellen Monat gekündigt hat
            if (createdAt && canceledAt && canceledAt > abrechnungsdatum) {
                nutzungszeit += Math.floor((canceledAt - createdAt) / 1000);
            }
            // Wenn Nutzer schon vor dem Abrechnungsmonat registriert war und nicht gekündigt hat
            if (createdAt && createdAt <= abrechnungsdatum && !canceledAt) {
                nutzungszeit += Math.floor((now - abrechnungsdatum) / 1000);
            }
            // Wenn Nutzer schon vor dem Abrechnungsmonat registriert war und im aktuellen Monat gekündigt hat
            if (createdAt && canceledAt && createdAt <= abrechnungsdatum && canceledAt > abrechnungsdatum) {
                nutzungszeit += Math.floor((canceledAt - abrechnungsdatum) / 1000);
            }
            // Wenn Nutzer im Vormonat gekündigt hat, keine Abrechnung mehr
            if (canceledAt && canceledAt <= abrechnungsdatum) {
                nutzungszeit = 0;
            }
            nutzerDaten.push({
                email: row.email,
                nutzungszeit,
                row
            });
            summeNutzungszeit += nutzungszeit;
        }
        // Abrechnung und Speicherung + Stripe-Abbuchung
        for (const nutzer of nutzerDaten) {
            if (nutzer.nutzungszeit === 0) continue;
            const kostenanteil = summeNutzungszeit > 0 ? (nutzer.nutzungszeit / summeNutzungszeit) * serverCosts : 0;
            await env.DB.prepare(
                'INSERT INTO billing_history (email, abrechnungsmonat, nutzungszeit, kostenanteil, timestamp) VALUES (?, ?, ?, ?, ?)'
            ).bind(
                nutzer.email,
                abrechnungsmonat,
                nutzer.nutzungszeit,
                kostenanteil,
                now.toISOString()
            ).run();
            // Stripe-Abbuchung nur für aktive Nutzer
            if (nutzer.row.payment_authorized && nutzer.row.stripe_id && kostenanteil > 0) {
                try {
                    // Stripe PaymentIntent erstellen (Betrag in Cent, EUR)
                    const paymentIntentBody = new URLSearchParams({
                        amount: Math.round(kostenanteil * 100).toString(),
                        currency: 'eur',
                        customer: nutzer.row.stripe_id, // stripe_id als customer_id gespeichert
                        description: `MAC-SMP Monatsbeitrag ${abrechnungsmonat}`,
                        confirm: 'true',
                        off_session: 'true',
                    });
                    // Wenn payment_method in DB vorhanden, an Stripe übergeben
                    if (nutzer.row.payment_method && nutzer.row.payment_method !== 'unknown' && nutzer.row.payment_method !== 'stripe') {
                        paymentIntentBody.append('payment_method', nutzer.row.payment_method);
                    }
                    paymentIntentBody.append('payment_method_types[]', 'card');
                    paymentIntentBody.append('payment_method_types[]', 'sepa_debit');
                    const paymentIntentRes = await fetch('https://api.stripe.com/v1/payment_intents', {
                        method: 'POST',
                        headers: {
                            'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
                            'Content-Type': 'application/x-www-form-urlencoded'
                        },
                        body: paymentIntentBody.toString(),
                    });
                    const paymentIntentData = await paymentIntentRes.json();
                    // Immer loggen, egal ob Erfolg oder Fehler
                    console.log('Stripe PaymentIntent Antwort:', paymentIntentData);
                    if (!paymentIntentRes.ok) {
                        // Fehlerbehandlung, z.B. E-Mail an Admin oder Logging
                        console.error('Stripe PaymentIntent Fehler:', paymentIntentData);
                    }
                } catch (err) {
                    // Stripe-Fehler loggen
                    console.error('Stripe PaymentIntent Exception:', err);
                }
            }
            // Sende E-Mail (Pseudo, da Worker keine SMTP hat)
            if (env.SEND_EMAIL && typeof sendMail === 'function') {
                await sendMail(nutzer.email, `Deine Abrechnung für ${abrechnungsmonat}`, `Du hast diesen Monat ${nutzer.nutzungszeit} Sekunden genutzt. Dein Anteil an den Serverkosten beträgt: ${kostenanteil.toFixed(2)} EUR.`);
            }
            // Reset used_seconds_this_month
            await env.DB.prepare('UPDATE payment_setups SET used_seconds_this_month = 0 WHERE email = ?').bind(nutzer.email).run();
        }
    }
}
