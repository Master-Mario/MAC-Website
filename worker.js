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

        // Hilfsfunktion: Stellt sicher, dass die Tabelle payment_setups existiert
        async function ensurePaymentSetupsTable(env) {
            // Prüfe, ob Tabelle existiert
            const check = await env.DB.prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='payment_setups';"
            ).first();
            if (!check) {
                // Tabelle anlegen (minecraft_uuid als PRIMARY KEY)
                await env.DB.prepare(`
                    CREATE TABLE payment_setups (
                        minecraft_uuid TEXT PRIMARY KEY,
                        email TEXT NOT NULL,
                        stripe_id TEXT NOT NULL,
                        payment_authorized BOOLEAN NOT NULL DEFAULT false,
                        payment_method TEXT NOT NULL DEFAULT 'unknown',
                        created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
                        canceled_at TEXT DEFAULT NULL,
                        used_seconds_this_month INTEGER NOT NULL DEFAULT 0
                    );
                `).run();
            } else {
                // Prüfe, ob Spalte created_at und canceled_at existieren, falls nicht, füge sie hinzu
                const columns = await env.DB.prepare("PRAGMA table_info(payment_setups);").all();
                const colArray = columns.results || columns; // Fallback falls .results nicht existiert
                if (!colArray.some(col => col.name === 'created_at')) {
                    await env.DB.prepare("ALTER TABLE payment_setups ADD COLUMN created_at TEXT;").run();
                    // Setze für bestehende Zeilen ein aktuelles Datum
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

        // Hilfsfunktion: Stellt sicher, dass die Tabelle billing_history existiert
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

        // Vorheriger Endpunkt: /create-checkout-session
        // ...existing code for /create-checkout-session wurde entfernt oder kommentiert...

        if (path === '/create-checkout-session' && method === 'POST') {
            await ensurePaymentSetupsTable(env);
            const body = await request.json();
            const { minecraftUsername } = body;
            // Discord-Session holen
            const token = getCookie(request, 'mac_sid');
            const session = token ? await verifyJWT(token) : null;
            const email = session?.user?.email;
            if (!email || !minecraftUsername) {
                return new Response(JSON.stringify({ error: 'Daten erforderlich (Discord-Login & Minecraft-Username)' }), {
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

            // Update payment_authorized und payment_method in der Datenbank
            try {
                await env.DB.prepare(
                    "UPDATE payment_setups SET payment_authorized = ?, payment_method = ? WHERE stripe_id = ?"
                )
                    .bind(true, "stripe", sessionId)
                    .run();
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
            // amount bis zum nächsten Zahltag (Ende des Monats)
            let amount = null;
            let next_pay = null;
            let nutzungsminuten = 0;
            if (row.created_at) {
                const serverKosten = parseFloat(env.SERVER_COSTS || '14');
                const jetzt = new Date();
                // Zahltag aus .env oder Monatsende
                let zahltag;
                if (env.ZAHLTAG) {
                    // env.ZAHLTAG als Tag des Monats interpretieren (z.B. "28")
                    const zahltagNum = parseInt(env.ZAHLTAG, 10);
                    if (!isNaN(zahltagNum) && zahltagNum > 0 && zahltagNum <= 31) {
                        // Prüfe, ob der Zahltag in diesem Monat noch kommt
                        let thisMonthZahltag = new Date(jetzt.getFullYear(), jetzt.getMonth(), zahltagNum, 23, 59, 59, 999);
                        if (jetzt <= thisMonthZahltag) {
                            zahltag = thisMonthZahltag;
                        } else {
                            // Nächster Monat
                            zahltag = new Date(jetzt.getFullYear(), jetzt.getMonth() + 1, zahltagNum, 23, 59, 59, 999);
                        }
                    } else {
                        // Fallback: Monatsende
                        zahltag = new Date(jetzt.getFullYear(), jetzt.getMonth() + 1, 0, 23, 59, 59, 999);
                    }
                } else {
                    zahltag = new Date(jetzt.getFullYear(), jetzt.getMonth() + 1, 0, 23, 59, 59, 999);
                }
                next_pay = zahltag.toISOString();
                // Alle Nutzer holen
                const nutzerRows = (await env.DB.prepare('SELECT created_at, canceled_at, email FROM payment_setups WHERE payment_authorized = 1').all()).results || [];
                // Nutzungsminuten berechnen
                let summeNutzerminuten = 0;
                let meineNutzerminuten = 0;
                for (const nutzer of nutzerRows) {
                    const reg = new Date(nutzer.created_at);
                    const end = nutzer.canceled_at ? new Date(nutzer.canceled_at) : zahltag;
                    const monatStart = new Date(jetzt.getFullYear(), jetzt.getMonth(), 1, 0, 0, 0, 0);
                    const start = reg > monatStart ? reg : monatStart;
                    const stop = end < zahltag ? end : zahltag;
                    let minuten = Math.max(0, Math.floor((stop - start) / 1000 / 60));
                    summeNutzerminuten += minuten;
                    if (nutzer.email === row.email) {
                        meineNutzerminuten = minuten;
                    }
                }
                nutzungsminuten = meineNutzerminuten;
                if (summeNutzerminuten > 0) {
                    amount = serverKosten * (meineNutzerminuten / summeNutzerminuten);
                } else {
                    amount = 0;
                }
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
                next_pay,
                amount: amount !== null ? parseFloat(amount.toFixed(2)) : null,
                nutzungsminuten
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
            // Kündigungsdatum auf nächsten Zahltag setzen
            try {
                // Hole aktuellen Eintrag
                const row = await env.DB.prepare('SELECT created_at FROM payment_setups WHERE email = ?').bind(session.user.email).first();
                let createdAt = row?.created_at ? new Date(row.created_at) : null;
                let now = new Date();
                // Zahltag aus .env oder Monatsende
                let zahltag;
                if (env.ZAHLTAG) {
                    // env.ZAHLTAG als Tag des Monats interpretieren (z.B. "28")
                    const zahltagNum = parseInt(env.ZAHLTAG, 10);
                    if (!isNaN(zahltagNum) && zahltagNum > 0 && zahltagNum <= 31) {
                        // Prüfe, ob der Zahltag in diesem Monat noch kommt
                        let thisMonthZahltag = new Date(now.getFullYear(), now.getMonth(), zahltagNum, 23, 59, 59, 999);
                        if (now <= thisMonthZahltag) {
                            zahltag = thisMonthZahltag;
                        } else {
                            // Nächster Monat
                            zahltag = new Date(now.getFullYear(), now.getMonth() + 1, zahltagNum, 23, 59, 59, 999);
                        }
                    } else {
                        // Fallback: Monatsende
                        zahltag = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59, 999);
                    }
                } else {
                    zahltag = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59, 999);
                }
                // Kündigung zum nächsten Zahltag
                await env.DB.prepare(
                    'UPDATE payment_setups SET canceled_at = ? WHERE email = ?'
                ).bind(zahltag.toISOString(), session.user.email).run();
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
        // Zahltag aus .env oder Monatsende
        let zahltag;
        if (env.ZAHLTAG) {
            zahltag = new Date(env.ZAHLTAG);
        } else {
            zahltag = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59, 999);
        }
        const serverKosten = parseFloat(env.SERVER_COSTS || '0');
        // Alle Nutzer (auch gekündigte) holen
        const rows = (await env.DB.prepare('SELECT * FROM payment_setups').all()).results || [];
        // Nutzertage berechnen
        let nutzerDaten = [];
        let summeNutzerminuten = 0;
        for (const row of rows) {
            const reg = row.created_at ? new Date(row.created_at) : null;
            const end = row.canceled_at ? new Date(row.canceled_at) : zahltag;
            const monatStart = new Date(now.getFullYear(), now.getMonth(), 1, 0, 0, 0, 0);
            // Startzeitpunkt für die Berechnung: max(registriert, Monatsanfang)
            const start = reg && reg > monatStart ? reg : monatStart;
            // Endzeitpunkt: min(zahltag, gekündigt)
            const stop = end < zahltag ? end : zahltag;
            let minuten = reg ? Math.max(0, Math.floor((stop - start) / 1000 / 60)) : 0;
            summeNutzerminuten += minuten;
            nutzerDaten.push({
                email: row.email,
                nutzungsminuten: minuten,
                row
            });
        }
        // Abrechnung und Speicherung
        for (const nutzer of nutzerDaten) {
            if (nutzer.nutzungsminuten === 0) continue;
            const kostenanteil = summeNutzerminuten > 0 ? (nutzer.nutzungsminuten / summeNutzerminuten) * serverKosten : 0;
            await env.DB.prepare(
                'INSERT INTO billing_history (email, abrechnungsmonat, nutzungszeit, kostenanteil, timestamp) VALUES (?, ?, ?, ?, ?)'
            ).bind(
                nutzer.email,
                abrechnungsmonat,
                nutzer.nutzungsminuten,
                kostenanteil,
                now.toISOString()
            ).run();
            // Sende E-Mail (Pseudo, da Worker keine SMTP hat)
            if (env.SEND_EMAIL && typeof sendMail === 'function') {
                await sendMail(nutzer.email, `Deine Abrechnung für ${abrechnungsmonat}`,
                    `Du warst diesen Monat ${nutzer.nutzungsminuten} Minuten registriert. Dein Anteil an den Serverkosten beträgt: ${kostenanteil.toFixed(2)} EUR.`);
            }
            // Reset used_seconds_this_month (optional, falls nicht mehr benötigt)
            await env.DB.prepare('UPDATE payment_setups SET used_seconds_this_month = 0 WHERE email = ?').bind(nutzer.email).run();
        }
    }
}
