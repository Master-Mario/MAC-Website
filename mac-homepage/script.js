// Smooth scrolling for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const targetId = this.getAttribute('href');
        // Check if the target is on the current page or another page
        if (targetId.startsWith('#')) { // Target is on the current page
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                targetElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        } else { // Target is on another page
            window.location.href = this.href;
        }
    });
});

// Navbar scroll effect
window.addEventListener('scroll', function() {
    const navbar = document.getElementById('navbar');
    if (navbar && window.scrollY > 50) { // Added null check for navbar
        navbar.classList.add('scrolled');
    } else if (navbar) {
        navbar.classList.remove('scrolled');
    }
});

// --- Auth Script Start ---

// Minecraft Server Status Abfrage
function fetchMinecraftServerStatus() {
    const statusText = document.getElementById('serverStatusText');
    const statusIndicator = document.getElementById('serverStatusIndicator');
    const playersOnline = document.getElementById('serverPlayersOnline');
    const playersMax = document.getElementById('serverPlayersMax');
    const playerListContainer = document.getElementById('playerListContainer');

    // Server-IP und Port
    const serverAddress = 'mac-netzwerk.net';
    const serverPort = 25565;

    // Offizielle Minecraft-Server Status API
    fetch(`https://api.minecraft.net/v1/server/status`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            address: serverAddress,
            port: serverPort
        })
    })
    .then(response => {
        // Fallback zur mcsrvstat.us API falls Mojang API Fehler zurückgibt
        if (!response.ok) {
            throw new Error('Mojang API nicht erreichbar');
        }
        return response.json();
    })
    .then(data => {
        if (data && data.online) {
            statusText.textContent = `Online`;
            statusText.style.color = '#27c93f';
            if (statusIndicator) {
                statusIndicator.style.display = 'inline-block';
                statusIndicator.style.background = '#27c93f';
                statusIndicator.style.boxShadow = '0 0 10px #27c93f';
                statusIndicator.style.width = '12px';
                statusIndicator.style.height = '12px';
                statusIndicator.style.borderRadius = '50%';
                statusIndicator.style.marginRight = '8px';
            }
            if (playersOnline && playersMax) {
                playersOnline.textContent = data.players && typeof data.players.online === 'number' ? data.players.online : '?';
                playersMax.textContent = data.players && typeof data.players.max === 'number' ? data.players.max : '?';
            }

            // Zeige Spielerliste an, falls vorhanden
            if (playerListContainer && data.players && data.players.sample && data.players.sample.length > 0) {
                playerListContainer.innerHTML = '';
                const playerList = document.createElement('div');
                playerList.className = 'player-list';

                const heading = document.createElement('h3');
                heading.textContent = 'Aktive Spieler';
                playerList.appendChild(heading);

                const list = document.createElement('ul');
                data.players.sample.forEach(player => {
                    const item = document.createElement('li');
                    item.className = 'player-item';
                    const playerHead = document.createElement('img');
                    playerHead.src = `https://crafatar.com/avatars/${player.id}?size=24&overlay`;
                    playerHead.alt = player.name;
                    playerHead.className = 'player-head';
                    item.appendChild(playerHead);

                    const playerName = document.createElement('span');
                    playerName.textContent = player.name;
                    item.appendChild(playerName);

                    list.appendChild(item);
                });
                playerList.appendChild(list);
                playerListContainer.appendChild(playerList);
                playerListContainer.style.display = 'block';
            } else if (playerListContainer) {
                playerListContainer.style.display = 'none';
            }
        } else {
            statusText.textContent = 'Offline';
            statusText.style.color = '#ff0023';
            if (statusIndicator) {
                statusIndicator.style.display = 'inline-block';
                statusIndicator.style.background = '#ff0023';
                statusIndicator.style.boxShadow = '0 0 10px #ff0023';
                statusIndicator.style.width = '12px';
                statusIndicator.style.height = '12px';
                statusIndicator.style.borderRadius = '50%';
                statusIndicator.style.marginRight = '8px';
            }
            if (playersOnline && playersMax) {
                playersOnline.textContent = '0';
                playersMax.textContent = '?';
            }
            if (playerListContainer) {
                playerListContainer.style.display = 'none';
            }
        }
    })
    .catch(() => {
        // Fallback zur mcsrvstat.us API
        fetch('https://api.mcsrvstat.us/2/mac-netzwerk.net')
            .then(response => response.json())
            .then(data => {
                if (data && data.online) {
                    statusText.textContent = `Online`;
                    statusText.style.color = '#27c93f';
                    if (statusIndicator) {
                        statusIndicator.style.display = 'inline-block';
                        statusIndicator.style.background = '#27c93f';
                        statusIndicator.style.boxShadow = '0 0 10px #27c93f';
                        statusIndicator.style.width = '12px';
                        statusIndicator.style.height = '12px';
                        statusIndicator.style.borderRadius = '50%';
                        statusIndicator.style.marginRight = '8px';
                    }
                    if (playersOnline && playersMax) {
                        playersOnline.textContent = data.players && typeof data.players.online === 'number' ? data.players.online : '?';
                        playersMax.textContent = data.players && typeof data.players.max === 'number' ? data.players.max : '?';
                    }

                    // Zeige Spielerliste an, falls vorhanden
                    if (playerListContainer && data.players && data.players.list && data.players.list.length > 0) {
                        playerListContainer.innerHTML = '';
                        const playerList = document.createElement('div');
                        playerList.className = 'player-list';

                        const heading = document.createElement('h3');
                        heading.textContent = 'Aktive Spieler';
                        playerList.appendChild(heading);

                        const list = document.createElement('ul');
                        data.players.list.forEach(playerName => {
                            const item = document.createElement('li');
                            item.className = 'player-item';
                            item.textContent = playerName;
                            list.appendChild(item);
                        });
                        playerList.appendChild(list);
                        playerListContainer.appendChild(playerList);
                        playerListContainer.style.display = 'block';
                    } else if (playerListContainer) {
                        playerListContainer.style.display = 'none';
                    }
                } else {
                    statusText.textContent = 'Offline';
                    statusText.style.color = '#ff0023';
                    if (statusIndicator) {
                        statusIndicator.style.display = 'inline-block';
                        statusIndicator.style.background = '#ff0023';
                        statusIndicator.style.boxShadow = '0 0 10px #ff0023';
                        statusIndicator.style.width = '12px';
                        statusIndicator.style.height = '12px';
                        statusIndicator.style.borderRadius = '50%';
                        statusIndicator.style.marginRight = '8px';
                    }
                    if (playersOnline && playersMax) {
                        playersOnline.textContent = '0';
                        playersMax.textContent = '?';
                    }
                    if (playerListContainer) {
                        playerListContainer.style.display = 'none';
                    }
                }
            })
            .catch(() => {
                statusText.textContent = 'Status nicht verfügbar';
                statusText.style.color = '#888';
                if (statusIndicator) {
                    statusIndicator.style.display = 'none';
                }
                if (playersOnline && playersMax) {
                    playersOnline.textContent = '?';
                    playersMax.textContent = '?';
                }
                if (playerListContainer) {
                    playerListContainer.style.display = 'none';
                }
            });
    });
}

document.addEventListener('DOMContentLoaded', () => {
    fetchMinecraftServerStatus();
    // Optional: alle 60 Sekunden neu abfragen
    setInterval(fetchMinecraftServerStatus, 60000);
});

document.addEventListener('DOMContentLoaded', () => {
    const discordLoginBtn = document.getElementById('discordLoginBtn');
    const userInfoDiv = document.getElementById('userInfo');
    const userAvatarImg = document.getElementById('userAvatar');
    const userNameSpan = document.getElementById('userName');
    const logoutBtn = document.getElementById('logoutBtn');

    // Mobile menu toggle
    const mobileMenuIcon = document.querySelector('.mobile-menu');
    const navLinks = document.querySelector('.nav-links');

    if (mobileMenuIcon && navLinks) {
        mobileMenuIcon.addEventListener('click', function() {
            console.log('Mobile menu icon geklickt!'); // Hinzugefügte Zeile für die Diagnose
            navLinks.classList.toggle('open'); // Toggle 'open' class
            console.log('Klassen von navLinks:', navLinks.className); // Hinzugefügte Zeile für die Diagnose
        });
    }
    // End of Mobile menu toggle

    // Logout Modal Elements
    const logoutConfirmationModal = document.getElementById('logoutConfirmationModal');
    const confirmLogoutBtn = document.getElementById('confirmLogoutBtn');
    const cancelLogoutBtn = document.getElementById('cancelLogoutBtn');

    const defaultAvatarUrl = '../logos/favicon-32x32.png'; // Path to your default avatar

    async function checkAuthStatus() {
        try {
            const response = await fetch('/api/auth/status', { // Geändert zu relativem Pfad
                credentials: 'include' // Wichtig für Cookies/Sessions
            });
            if (!response.ok) {
                console.error('Auth status check failed:', response.status);
                displayLoggedOutState();
                return;
            }
            const data = await response.json();
            if (data.loggedIn && data.user) {
                displayLoggedInState(data.user);
            } else {
                displayLoggedOutState();
            }
        } catch (error) {
            console.error('Error checking auth status:', error);
            displayLoggedOutState();
        }
    }

    function displayLoggedInState(user) {
        if (discordLoginBtn) discordLoginBtn.style.display = 'none';
        if (userInfoDiv) userInfoDiv.style.display = 'flex';
        if (userNameSpan) userNameSpan.textContent = user.username;
        if (userAvatarImg) {
            if (user.id && user.avatar) {
                userAvatarImg.src = `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`;
            } else {
                userAvatarImg.src = defaultAvatarUrl;
            }
        }
        // Dropdown-Menü nur einmal einfügen
        if (userInfoDiv && !document.getElementById('profileDropdown')) {
            const dropdown = document.createElement('div');
            dropdown.className = 'profile-dropdown';
            dropdown.id = 'profileDropdown';
            dropdown.innerHTML = `
                <ul>
                    <li class="profile-link" id="profileMenuProfile">Profil</li>
                    <li class="profile-link logout-link" id="profileMenuLogout">Abmelden</li>
                </ul>
            `;
            userInfoDiv.appendChild(dropdown);

            // Menüeinträge: Profil/Abmelden
            document.getElementById('profileMenuLogout').addEventListener('click', showLogoutModal);
            document.getElementById('profileMenuProfile').addEventListener('click', function() {
                window.location.href = '/profile';
            });
        }
    }

    function displayLoggedOutState() {
        if (discordLoginBtn) discordLoginBtn.style.display = 'flex';
        if (userInfoDiv) userInfoDiv.style.display = 'none';
    }

    function showLogoutModal() {
        if (logoutConfirmationModal) {
            logoutConfirmationModal.classList.add('open');
        }
    }

    function hideLogoutModal() {
        if (logoutConfirmationModal) {
            logoutConfirmationModal.classList.remove('open');
        }
    }

    async function performActualLogout() {
        try {
            const response = await fetch('/logout', { // Geändert zu relativem Pfad
                method: 'GET',
                credentials: 'include'
            });
            if (response.ok) {
                displayLoggedOutState();
                window.location.reload(); // Seite nach Logout neu laden
            } else {
                console.error('Logout failed:', response.status);
                alert('Logout fehlgeschlagen.');
            }
        } catch (error) {
            console.error('Error during logout:', error);
            alert('Fehler beim Logout.');
        }
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', (event) => {
            event.preventDefault(); // Prevent any default action
            showLogoutModal();
        });
    }

    if (confirmLogoutBtn) {
        confirmLogoutBtn.addEventListener('click', () => {
            hideLogoutModal();
            performActualLogout();
        });
    }

    if (cancelLogoutBtn) {
        cancelLogoutBtn.addEventListener('click', () => {
            hideLogoutModal();
        });
    }

    // Close modal if user clicks on the overlay itself
    if (logoutConfirmationModal) {
        logoutConfirmationModal.addEventListener('click', (event) => {
            if (event.target === logoutConfirmationModal) {
                hideLogoutModal();
            }
        });
    }

    // Dropdown-Logik
    if (userAvatarImg) {
        userAvatarImg.style.cursor = 'pointer';
        userAvatarImg.addEventListener('click', function(e) {
            e.stopPropagation();
            const dropdown = document.getElementById('profileDropdown');
            if (dropdown) {
                dropdown.classList.toggle('open');
            }
        });
    }
    // Schließe Dropdown bei Klick außerhalb
    document.addEventListener('click', function(e) {
        const dropdown = document.getElementById('profileDropdown');
        if (dropdown && dropdown.classList.contains('open')) {
            if (!dropdown.contains(e.target) && e.target !== userAvatarImg) {
                dropdown.classList.remove('open');
            }
        }
    });

    // Initial check
    checkAuthStatus();
});
// --- Auth Script End ---

// --- Stripe Payment Script Start ---
document.addEventListener('DOMContentLoaded', () => {
    const registrationForm = document.getElementById('registrationForm');
    const paymentMessage = document.getElementById('payment-message');

// --- Cookie Banner Script ---
document.addEventListener('DOMContentLoaded', function() {
    // Cookie-Banner dynamisch einfügen, falls noch nicht vorhanden
    if (!document.getElementById('cookieBanner')) {
        const banner = document.createElement('div');
        banner.id = 'cookieBanner';
        banner.className = 'cookie-banner';
        banner.innerHTML = `
            <div class="cookie-banner-overlay"></div>
            <div class="cookie-banner-center">
                <div class="cookie-banner-content">
                    <span class="cookie-banner-text">Diese Website verwendet Cookies für Login. Mehr dazu in der <a href="datenschutz.html" target="_blank">Datenschutzerklärung</a>.</span>
                    <button id="acceptCookiesBtn" class="cookie-banner-btn">Verstanden</button>
                </div>
            </div>
        `;
        document.body.appendChild(banner);
    }
    const cookieBanner = document.getElementById('cookieBanner');
    const acceptBtn = document.getElementById('acceptCookiesBtn');
    // Cookie prüfen
    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
    }
    function setCookie(name, value, days) {
        let expires = '';
        if (days) {
            const date = new Date();
            date.setTime(date.getTime() + (days*24*60*60*1000));
            expires = "; expires=" + date.toUTCString();
        }
        document.cookie = name + "=" + (value || "") + expires + "; path=/; SameSite=Lax";
    }
    function disablePage(disabled) {
        if (disabled) {
            // Blockiere alle Interaktionen, aber ohne Blur/Filter
            document.body.classList.add('cookies-blocked');
            // Füge einen unsichtbaren Overlay-Div hinzu, falls nicht vorhanden
            if (!document.getElementById('cookieBlockerOverlay')) {
                const overlay = document.createElement('div');
                overlay.id = 'cookieBlockerOverlay';
                overlay.style.position = 'fixed';
                overlay.style.inset = '0';
                overlay.style.width = '100vw';
                overlay.style.height = '100vh';
                overlay.style.zIndex = '2999';
                overlay.style.background = 'transparent';
                overlay.style.pointerEvents = 'all';
                overlay.tabIndex = 0;
                overlay.setAttribute('aria-hidden', 'true');
                document.body.appendChild(overlay);
            }
        } else {
            document.body.classList.remove('cookies-blocked');
            // Entferne Overlay falls vorhanden
            const overlay = document.getElementById('cookieBlockerOverlay');
            if (overlay) overlay.remove();
        }
    }
    if (getCookie('mac_cookies_accepted') === '1') {
        cookieBanner.classList.add('hide');
        disablePage(false);
        const overlay = document.querySelector('.cookie-banner-overlay');
        if (overlay) overlay.style.display = 'none';
    } else {
        cookieBanner.classList.remove('hide');
        disablePage(true);
    }
    if (acceptBtn) {
        acceptBtn.addEventListener('click', function() {
            setCookie('mac_cookies_accepted', '1', 365);
            cookieBanner.classList.add('hide');
            disablePage(false);
            const overlay = document.querySelector('.cookie-banner-overlay');
            if (overlay) overlay.style.display = 'none';
        });
    }
});

// --- Registrierung/Login Sichtbarkeit für SMP-Formular ---
document.addEventListener('DOMContentLoaded', () => {
    const registrationSection = document.getElementById('registrationSection');
    const loginPromptSection = document.getElementById('loginPromptSection');
    const bigDiscordLoginBtn = document.getElementById('bigDiscordLoginBtn');
    // NEU: Section für "Für MAC-SMP registrieren & Kosten"
    const smpSection = document.getElementById('mac-smp-registrierung');

    async function checkSmpAuthAndShowForm() {
        try {
            const response = await fetch('/api/auth/status', { credentials: 'include' });
            if (!response.ok) throw new Error('Status nicht OK');
            const data = await response.json();
            if (data.loggedIn && data.user) {
                // Prüfe, ob User bereits registriert ist (Abo vorhanden)
                const aboRes = await fetch('/api/d1/abo-status', { credentials: 'include' });
                if (aboRes.ok) {
                    const abo = await aboRes.json();
                    // Formular ausblenden, wenn aktiv ODER gekündigt aber Kündigungsdatum in der Zukunft
                    if (abo && ((abo.active && !abo.canceled_at) || (abo.canceled_at && new Date(abo.canceled_at) > new Date()))) {
                        if (smpSection) smpSection.style.display = 'none';
                        return;
                    }
                }
                // User ist eingeloggt, aber nicht aktiv registriert oder Kündigung ist abgelaufen: Formular anzeigen
                if (registrationSection) registrationSection.style.display = 'block';
                if (loginPromptSection) loginPromptSection.style.display = 'none';
                if (smpSection) smpSection.style.display = '';
            } else {
                if (registrationSection) registrationSection.style.display = 'none';
                if (loginPromptSection) loginPromptSection.style.display = 'block';
                if (smpSection) smpSection.style.display = '';
            }
        } catch (e) {
            if (registrationSection) registrationSection.style.display = 'none';
            if (loginPromptSection) loginPromptSection.style.display = 'block';
            if (smpSection) smpSection.style.display = '';
        }
    }
    if (bigDiscordLoginBtn) {
        bigDiscordLoginBtn.addEventListener('click', function(e) {
            e.preventDefault();
            window.location.href = '/login';
        });
    }
    checkSmpAuthAndShowForm();
});
// --- Registrierung/Login Sichtbarkeit für SMP-Formular ---
document.addEventListener('DOMContentLoaded', async function() {
        // ...existing code...
        const paymentMethodEl = document.getElementById('aboPaymentMethod');
        // ...existing code...
        let abo = null;
        try {
            const res = await fetch('/api/d1/abo-status', { credentials: 'include' });
            if (res.ok) {
                abo = await res.json();
                // Zahlungsart bestimmen
                let paymentMethod = '-';
                if (abo.stripe_id && abo.stripe_id !== '' && abo.active) {
                    paymentMethod = 'Stripe';
                } else if ((!abo.stripe_id || abo.stripe_id === '') && abo.active) {
                    paymentMethod = 'Guthaben';
                } else if (!abo.active) {
                    paymentMethod = '-';
                }
                if (paymentMethodEl) paymentMethodEl.textContent = paymentMethod;
                // Felder nur anzeigen, wenn aktiv
                const detailsDiv = document.querySelector('.abo-details');
                if (detailsDiv) {
                    detailsDiv.style.display = (abo.active ? '' : 'none');
                }
                // ...existing code...
            } else {
                // ...existing code...
                if (paymentMethodEl) paymentMethodEl.textContent = '-';
                const detailsDiv = document.querySelector('.abo-details');
                if (detailsDiv) detailsDiv.style.display = 'none';
            }
        } catch (e) {
            // ...existing code...
            if (paymentMethodEl) paymentMethodEl.textContent = '-';
            const detailsDiv = document.querySelector('.abo-details');
            if (detailsDiv) detailsDiv.style.display = 'none';
        }
        // ...existing code...
    });
